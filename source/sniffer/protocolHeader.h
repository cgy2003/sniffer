#pragma once
#ifndef PROTOCOLHEADER_H
#define PROTOCOLHEADER_H

#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321	 

#define PROTOCOL_ICMP 1
#define PROTOCOL_TCP 6					
#define PROTOCOL_UDP 17	


struct EthernetHeader {
	unsigned char destMac[6];   // 目的 MAC 地址
	unsigned char srcMac[6];  // 源 MAC 地址
	unsigned short etherType;   // 以太网类型
};

struct ArpHeader {
	unsigned short hardwareType;    // 硬件类型
	unsigned short protocolType;    // 协议类型
	unsigned char hardwareAddrLen;    // 硬件地址长度
	unsigned char protocolAddrLen;    // 协议地址长度
	unsigned short operation;       // ARP操作码
	unsigned char senderHardwareAddr[6];  // 发送方硬件地址（MAC地址）
	unsigned char senderProtocolAddr[4];  // 发送方协议地址（IP地址）
	unsigned char targetHardwareAddr[6];  // 目标硬件地址（MAC地址）
	unsigned char targetProtocolAddr[4];  // 目标协议地址（IP地址）
};

struct IpHeader {
#if defined(BIG_ENDIAN)
	unsigned char version : 4; // 版本
	unsigned char headerLength : 4; // 首部长度
#elif defined(LITTLE_ENDIAN)
	unsigned char headerLength : 4; // 首部长度
	unsigned char version : 4; // 版本
#endif
	unsigned char typeOfService; // 服务类型
	unsigned short totalLength; // 总长度
	unsigned short identification; // 标识
	unsigned short flags ; // 标志位
	
	unsigned char timeToLive; // 存活时间
	unsigned char protocol; // 协议
	unsigned short headerChecksum; // 首部校验和
	unsigned char sourceIpAddress[4]; // 源IP地址
	unsigned char destinationIpAddress[4]; // 目的IP地址
};
struct TcpHeader {
	unsigned short sourcePort;     // 源端口号
	unsigned short destPort;     // 目标端口号
	unsigned int sequenceNumber;   // 序列号
	unsigned int ackNumber;      // 确认号

#if defined(LITTLE_ENDIAN)
	u_short reserved : 4,
		dataOffset : 4,
		fin : 1,
		syn : 1,
		rst : 1,
		psh : 1,
		ack : 1,
		urg : 1,
		ece : 1,
		cwr : 1;
#elif defined(BIG_ENDIAN)
	u_short dataOffset : 4,
		reserved : 4,
		cwr : 1,
		ece : 1,
		urg : 1,
		ack : 1,
		psh : 1,
		rst : 1,
		syn : 1,
		fin : 1;
#endif
	unsigned short window;       // 窗口大小
	unsigned short checksum;     // 校验和
	unsigned short urgentPointer;  // 紧急指针
};
struct UdpHeader {
	unsigned short sourcePort;   // 源端口号
	unsigned short destPort;   // 目标端口号
	unsigned short length;     // 数据包长度
	unsigned short checksum;   // 校验和
};
struct IcmpHeader {
	unsigned char type;       // 类型
	unsigned char code;       // 代码
	unsigned char checksum;    // 校验和

	unsigned char seq; // 序列号
};
struct IPv6Header {
	unsigned int version : 4;      // 版本
	unsigned int trafficClass : 8;   // 通信流量等级
	unsigned int flowLabel : 20;     // 流标签
	unsigned short payloadLength;    // 负载长度
	unsigned char nextHeader;      // 下一个头部
	unsigned char hopLimit;      // 跳限制
	unsigned short sourceAddress[8];   // 源IPv6地址
	unsigned short destinationAddress[8]; // 目的IPv6地址
};
struct Icmpv6Header
{
	unsigned char type;			//8位 类型
	unsigned char code;			//8位 代码
	unsigned char seq;			//序列号 8位
	unsigned char chksum;		//8位校验和
	unsigned char op_type;	//选项：类型
	unsigned char op_len;		//选项：长度
	unsigned char op_ethaddr[6];		//选项：链路层地址
};
struct data_save
{
	char save_type[8];
	int len;
	int time[8];
	struct EthernetHeader* ethernet_header;
	struct ArpHeader* arp_header;
	struct IpHeader* ip_header;
	struct TcpHeader* tcp_header;
	struct UdpHeader* udp_header;
	struct IcmpHeader* icmp_header;
	struct IPv6Header* ipv6_header;
	struct Icmpv6Header* icmpv6_header;
	void* app_header;

};
#endif