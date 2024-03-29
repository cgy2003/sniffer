# 项目文档

## 概述

### 运行环境

- 操作系统：Win10及以上

### 编译工具

- Visual Studio 2022
- MFC 14.3 及以上版本
- WinPcap 4.1.2版本


## 主要算法

### 网络数据包捕获分析

1. **使用`pcap_next_ex`函数循环捕获网络数据包**。

2. **使用`analyze_frame`函数分析捕获的网络数据包，解析以太网帧的头部信息，根据帧类型分发到相应的处理函数进行进一步的解析：**
   
   - 如果是 ARP 帧，则调用 `analyze_arp` 函数进行处理。
   - 如果是 IPv4 帧，则调用 `analyze_ip` 函数进行处理：
   
   - - 将 iph 中的各个字段信息复制到 data->ip_header 结构体中，再通过 switch 语句检查iph->protocol 的值，以确定下一个调用的函数：
       - 如果协议号是 1，则调用 analyze_icmp6 函数。
	    - 如果协议号是 6，则调用 analyze_tcp 函数。
	    - 如果协议号是 7，则调用 analyze_udp 函数。 
	
   
   - 如果是 IPv6 帧，则调用 `analyze_ip6` 函数进行处理：将 iph6 中的各个字段信息复制到 data->ipv6_header 结构体中，再通过 switch 语句检查 iph6->nextHeader 的值，以确定下一个头部的类型：
   	- 如果下一个头部是 0x3a，则调用 analyze_icmp6 函数。
   	- 如果下一个头部是 0x06，则调用 analyze_tcp 函数。
   	- 如果下一个头部是 0x11，则调用 analyze_udp 函数。 
   
   经过一系列函数的调用完成对数据包的解析，并将相应的信息保存在data中。
   
   

### IP报文重组

1. **查找本地数据包位置**：
   - 使用`FindIndex`方法在本地数据链表中查找指定索引位置的数据包。
2. **获取数据包结构体指针**：
   - 通过找到的位置获取指向数据包结构体的指针。
3. **提取标志位和偏移量**：
   - 从IPv4包头中提取标志位和偏移量的信息，用于后续的分片重组。
4. **处理不可分段的IP包和未实际分段的IP包**：
   - 根据标志位和偏移量的值，判断数据包是否为不可分段的IP包或者可分段但未实际分段的IP包，若是则弹出消息框并返回。
5. **查找第一个IP包及其索引**：
   - **初始化**：
     - `first`被初始化为NULL，用于存储第一个满足条件的数据包的指针。
     - `bpthis`被用于将传递的参数`lpParameter`转换为相应的类指针（CsnifferDlg类的指针）。
   - **提取标志位和偏移量**：
     - 从当前数据包的IP头中提取标志位（flags）和偏移量（offset）的信息。
   - **检查当前数据包是否满足条件**：
     - 如果标志位为1（表示分段）且偏移量为0，则将`first`指向当前数据包，并结束函数。这表示找到了第一个满足条件的数据包。
   - **循环查找**：
     - 如果当前数据包不满足条件，进入循环。
     - 在循环中，通过递减`index`来获取链表中的前一个位置，然后通过`FindIndex`方法获取该位置的数据包指针。
     - 如果找到的数据包的identification字段与当前数据包相同，则更新`tmp`指向该数据包，并调用`updateFlagOffset`更新标志位和偏移量。
     - 如果回溯到链表头部仍未找到满足条件的数据包，则返回NULL。
   - **设置第一个满足条件的数据包指针**：
     - 将`first`指向当前数据包，表示找到了第一个满足条件的数据包。
   - **返回结果**：
     - 返回指向第一个满足条件的数据包的指针（如果找到），否则返回NULL。
6. **初始化标志位和偏移量**：
   - 初始化标志位和偏移量，为后续循环处理做准备。
7. **获取网络数据和重组包规则结构体**：
   - 从网络数据链表中获取指定索引位置的数据，并初始化重组包规则结构体。
8. **初始化重组后的数据**：
   - 分配内存并拷贝第一个包的数据，初始化总长度。
9. **循环处理分段IP包**：
   - **循环条件**：
     - 循环首先检查`flag`是否为0，`offset`是否不为0，以及当前处理的数据包（`res`）的identification字段是否与`first`指向的数据包的identification字段相同。这个条件是为了确定是否继续合并相邻的数据包。
   - **索引更新和获取下一个数据包**：
     - 在每次循环中，索引`index`递增，然后通过链表的`FindIndex`方法获取链表中下一个位置的数据包指针，存储在`first`中。这确保循环在链表中向后移动。
   - **检查identification字段**：
     - 检查`first`指向的数据包的identification字段是否与`res`指向的数据包相同。如果相同，说明它们属于同一个IP分片，可以进行合并操作。
   - **更新标志位和偏移量和长度信息**：
     - 提取当前数据包的标志位和偏移量信息，以便后续使用。这是因为在IP分片中，数据包的偏移量用于确定数据包在原始数据中的位置。更新`prelen`和`sumlen`，其中`prelen`保存上一个数据包的总长度，`sumlen`保存当前数据包的总长度。这是为了在合并数据时准确计算新的总长度。
   - **获取nerworkData和追加数据**：
     - 通过链表中的位置获取当前数据包的`networkData`，并调用`combineData`函数将当前数据包的有效载荷与前一个数据包的有效载荷合并。这确保了数据的完整性。
   - **处理不同identification的情况**：
     - 如果当前数据包的identification字段与`res`指向的数据包不同，说明它们不属于同一个IP分片，直接跳过，不进行合并操作。这是因为每个IP分片有唯一的identification标识。
10. **更新长度和重组数据**：

- 如果重组后的数据存在，计算新的IP包长度，更新数据包中的长度字段，并更新详细信息和数据包。

流程图如下：

<img src=".\png\ip.drawio.png" alt="image-20231228150611918" style="zoom: 33%;" />

## 主要数据结构

1. **`struct EthernetHeader`**：
   - 该结构体定义了以太网帧的头部信息，包括目的 MAC 地址 (`destMac`)、源 MAC 地址 (`srcMac`) 和以太网类型 (`etherType`) 等字段。
2. **`struct ArpHeader`**：
   - 该结构体定义了 ARP 协议报文的头部信息，包括硬件类型 (`hardwareType`)、协议类型 (`protocolType`)、操作码 (`operation`) 以及发送方和目标方的硬件地址和协议地址等字段。
3. **`struct IpHeader`**：
   - 这个结构体定义了 IPv4 数据包的头部信息，包括版本 (`version`)、服务类型 (`typeOfService`)、总长度 (`totalLength`)、标识 (`identification`)、标志位和偏移量 (`flags`)、存活时间 (`timeToLive`)、协议 (`protocol`)、首部校验和 (`headerChecksum`) 以及源 IP 地址和目的 IP 地址等字段。
4. **`struct TcpHeader`** 和 **`struct UdpHeader`**：
   - 分别定义了 TCP 和 UDP 协议的头部信息。TCP 头部包含了源端口 (`sourcePort`)、目标端口 (`destPort`)、序列号 (`sequenceNumber`)、确认号 (`ackNumber`)、窗口大小 (`window`)、校验和 (`checksum`) 等字段。而 UDP 头部包含了源端口 (`sourcePort`)、目标端口 (`destPort`)、数据包长度 (`length`) 和校验和 (`checksum`) 等字段。
5. **`struct IcmpHeader`** 和 **`struct Icmpv6Header`**：
   - 分别定义了 ICMPv4 和 ICMPv6 协议的头部信息。ICMPv4 头部包含了类型 (`type`)、代码 (`code`)、校验和 (`checksum`) 和序列号 (`seq`) 等字段。ICMPv6 头部包含了类型 (`type`)、代码 (`code`)、校验和 (`chksum`)、序列号 (`seq`) 以及选项信息如选项类型 (`op_type`)、选项长度 (`op_len`) 和链路层地址 (`op_ethaddr`) 等字段。
6. **`struct IPv6Header`**：
   - 这个结构体定义了 IPv6 数据包的头部信息，包括版本 (`version`)、通信流量等级 (`trafficClass`)、流标签 (`flowLabel`)、负载长度 (`payloadLength`)、下一个头部 (`nextHeader`)、跳限制 (`hopLimit`)、源 IPv6 地址和目的 IPv6 地址等字段。
7. **`struct data_save`**：
   - 这个结构体是一个通用的数据保存结构，包含了不同协议数据包的头部信息指针和其他相关信息，例如数据包的长度 (`len`)、时间信息 (`time`)、以太网头部指针 (`ethernet_header`)、ARP 头部指针 (`arp_header`)、IP 头部指针 (`ip_header`)、TCP 头部指针 (`tcp_header`)、UDP 头部指针 (`udp_header`)、ICMP 头部指针 (`icmp_header`)、IPv6 头部指针 (`ipv6_header`)、ICMPv6 头部指针 (`icmpv6_header`)，以及一个通用的应用层头部指针 (`app_header`)，可以用于保存不同类型数据包的信息。



## 程序测试

### 网卡选择

<img src=".\png\image-20231228150611918.png" alt="image-20231228150611918" style="zoom: 33%;" />

### 过滤器设置

过滤器规则采用的是pcap过滤规则，下面选取两个典型规则进行测试：

1. ip src 源ip地址：侦听指定来源IP 地址的数据包

<img src=".\png\image-20231228151058876.png" alt="image-20231228151058876" style="zoom: 50%;" />

2. ip dst 目的IP地址:侦听指定目的IP 地址的数据包

<img src=".\png\image-20231228151323300.png" alt="image-20231228151323300" style="zoom: 50%;" />

### 解析显示数据包

<img src=".\png\image-20231228160830781.png" alt="image-20231228160830781" style="zoom: 50%;" />

<img src=".\png\image-20231228160903136.png" alt="image-20231228160903136" style="zoom:50%;" />

<img src=".\png\image-20231228160916399.png" alt="image-20231228160916399" style="zoom:50%;" />

对于每一个数据包，其各层协议头信息均可以正确显示出来。

### 数据包原始数据

![image-20231228172718312](C:\Users\Lenovo\AppData\Roaming\Typora\typora-user-images\image-20231228172718312.png)

以十六进制显示出数据包的原始内容

### 包重组

利用虚拟机对主机ping一个有效载荷数据大小为10000字节的ICMP的数据包，抓包如下：

<img src=".\png\image-20231228173703628.png" alt="image-20231228173703628" style="zoom:67%;" />

点击分析，再点击IP重组，可得到重组报文的信息：

<img src=".\png\image-20231228173812031.png" alt="image-20231228173812031" style="zoom: 50%;" />

由于总长度还包含了ICMP header 8 字节，IP header 20 字节，故总长度是10028字节。

### 保存文件

点击文件->保存

<img src=".\png\image-20231229172634312.png" alt="image-20231229172634312" style="zoom: 33%;" />

保存成功

<img src=".\png\image-20231229172911822.png" alt="image-20231229172911822" style="zoom:50%;" />

### 打开已有文件

<img src=".\png\image-20231229173347836.png" alt="image-20231229173347836" style="zoom: 33%;" />

## 遇到的问题和解决办法

1. 对于数据包不知道如何去处理

   解决办法：在网上搜集资料，参考别人的处理办法，最终采取层层分析的办法，先解析以太网帧的头部信息，分析帧类型是ip，arp还是ipv6，然后再类似地分析下一层信息，将信息保存到对应的结构体中即可

2. 对于结构体中变量的精细字段（如ip头部标志位中RSV,DF,MF的值）如何准确获取

   解决办法：采取位操作提取相应字段。
   
   

## 体会和建议

通过这次大作业，我深入研究了数据包捕获和分析的过程，对各层头部结构有了详细了解。同时，通过MFC框架的开发，我获得了对桌面应用程序开发的实际经验，提升了对Windows平台下应用程序的理解和掌握。这次经历让我更加熟悉网络通信和桌面应用开发，为我的技能和知识水平的提升提供了宝贵的机会。





