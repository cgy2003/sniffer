#include "framework.h"
#include "packet_analysis.h"
#include "pch.h"
#include "protocolHeader.h"


int analyze_arp(const unsigned char* packet, data_save* data)
{
    int i;
    struct ArpHeader* arph = (struct ArpHeader*)packet;

    // Ϊarp_header�ֶη����ڴ�
    data->arp_header = (struct ArpHeader*)malloc(sizeof(struct ArpHeader));
    if (!data->arp_header)
        return -1;

    // ����IP��MAC��ַ
    for (i = 0; i < 6; i++)
    {
        if (i < 4)
        {
            data->arp_header->targetProtocolAddr[i] = arph->targetProtocolAddr[i];
            data->arp_header->senderProtocolAddr[i] = arph->senderProtocolAddr[i];
        }
        data->arp_header->targetHardwareAddr[i] = arph->targetHardwareAddr[i];
        data->arp_header->senderHardwareAddr[i] = arph->senderHardwareAddr[i];
    }

    // ���������ֶβ������ֽ���ת��
    data->arp_header->protocolAddrLen = arph->protocolAddrLen;
    data->arp_header->protocolType = ntohs(arph->protocolType);
    data->arp_header->operation = ntohs(arph->operation);
    data->arp_header->hardwareAddrLen = arph->hardwareAddrLen;
    data->arp_header->hardwareType = ntohs(arph->hardwareType);

    // ��"ARP"�ַ������Ƶ�save_type�ֶ���
    strcpy(data->save_type, "ARP");

    return 1;
}

int analyze_icmp(const unsigned char* packet, struct data_save* data)
{
    struct IcmpHeader* icmph = (struct IcmpHeader*)packet;
    data->icmp_header = (struct IcmpHeader*)malloc(sizeof(struct IcmpHeader));
    if (!data->icmp_header)
        return -1;
    data->icmp_header->checksum = icmph->checksum;
    data->icmp_header->code = icmph->code;
    data->icmp_header->seq = icmph->seq;
    data->icmp_header->type = icmph->type;
    strcpy(data->save_type, "ICMP");
    return 1;
}

int analyze_icmp6(const unsigned char* packet, data_save* data)
{
    int i;
    struct Icmpv6Header* icmph6 = (struct Icmpv6Header*)packet;
    data->icmpv6_header = (struct Icmpv6Header*)malloc(sizeof(struct Icmpv6Header));

    if (!data->icmpv6_header)
        return -1;

    data->icmpv6_header->chksum= icmph6->chksum;
    data->icmpv6_header-> code= icmph6->code;
    data->icmpv6_header-> type= icmph6->type;
    data->icmpv6_header->seq= icmph6->seq;
    data->icmpv6_header->op_len= icmph6->op_len;
    data->icmpv6_header-> op_type= icmph6->op_type;
    for (i = 0; i < 6; i++)
    {
        data->icmpv6_header->op_ethaddr[i] = icmph6->op_ethaddr[i];
    }
    strcpy(data->save_type, "ICMPv6");
    
    return 1;
}

int analyze_tcp(const unsigned char* packet, struct data_save* data)
{
    struct TcpHeader* tcph = (struct TcpHeader*)packet;

    // Ϊtcp_header�ֶη����ڴ�
    data->tcp_header = (struct TcpHeader*)malloc(sizeof(struct TcpHeader));
    if (!data->tcp_header)
        return -1;

    // ����TCPͷ���ֶβ������ֽ���ת��
    data->tcp_header->sourcePort = ntohs(tcph->sourcePort);
    data->tcp_header->destPort = ntohs(tcph->destPort);
    data->tcp_header->sequenceNumber = ntohl(tcph->sequenceNumber);
    data->tcp_header->ackNumber = ntohl(tcph->ackNumber);
    data->tcp_header->dataOffset = tcph->dataOffset;
    data->tcp_header->reserved = tcph->reserved;
    data->tcp_header->cwr = tcph->cwr;
    data->tcp_header->ece = tcph->ece;
    data->tcp_header->urg = tcph->urg;
    data->tcp_header->ack = tcph->ack;
    data->tcp_header->psh = tcph->psh;
    data->tcp_header->rst = tcph->rst;
    data->tcp_header->syn = tcph->syn;
    data->tcp_header->fin = tcph->fin;
    data->tcp_header->window = ntohs(tcph->window);
    data->tcp_header->checksum = ntohs(tcph->checksum);
    data->tcp_header->urgentPointer = ntohs(tcph->urgentPointer);
    if (ntohs(tcph->sourcePort) == 80 || ntohs(tcph->destPort) == 80)
    {
        
        strcpy(data->save_type, "HTTP");
    }
    else  if (ntohs(tcph->sourcePort) == 443 || ntohs(tcph->destPort) == 443) {
        
        strcpy(data->save_type, "HTTPS");
    }
    else  if (ntohs(tcph->sourcePort) == 21 || ntohs(tcph->destPort) == 21) {

        strcpy(data->save_type, "FTP");
    }
    else  if (ntohs(tcph->sourcePort) == 23 || ntohs(tcph->destPort) == 23) {

        strcpy(data->save_type, "TELNET");
    }
    else   {

        strcpy(data->save_type, "TCP");
    }
    return 1;
    
}

int analyze_udp(const unsigned char* packet, struct data_save* data)
{
    struct UdpHeader* udph = (struct UdpHeader*)packet;

    // Ϊudp_header�ֶη����ڴ�
    data->udp_header = (struct UdpHeader*)malloc(sizeof(struct UdpHeader));
    if (!data->udp_header)
        return -1;

    // ����UDPͷ���ֶβ������ֽ���ת��
    data->udp_header->sourcePort = ntohs(udph->sourcePort);
    data->udp_header->destPort = ntohs(udph->destPort);
    data->udp_header->length = ntohs(udph->length);
    data->udp_header->checksum = ntohs(udph->checksum);

    if (ntohs(udph->sourcePort) == 53 || ntohs(udph->destPort) == 53)
        strcpy(data->save_type, "DNS");
    else if (ntohs(udph->sourcePort) == 68 || ntohs(udph->destPort) == 68)
        strcpy(data->save_type, "DHCP");
    else
        strcpy(data->save_type, "UDP");
    return 0;
}

int analyze_ip(const unsigned char* packet, struct data_save* data)
{
    int i;
    struct IpHeader* iph = (struct IpHeader*)packet;

    data->ip_header = (struct IpHeader*)malloc(sizeof(struct IpHeader));
    if (NULL == data->ip_header)
        return -1;
    
    data->ip_header->version = iph->headerLength;
    data->ip_header->headerChecksum = iph->headerChecksum;
    
    for (i = 0; i < 4; i++)
    {
     data->ip_header->sourceIpAddress[i] = iph->sourceIpAddress[i];
     data->ip_header->destinationIpAddress[i] = iph->destinationIpAddress[i];
    }

    /*data->ip_header->fragmentOffset = ntohs(iph->fragmentOffset);*/
    data->ip_header->identification = ntohs(iph->identification);
    data->ip_header->protocol = iph->protocol;
    data->ip_header->totalLength = ntohs(iph->totalLength);
    data->ip_header->typeOfService = iph->typeOfService;
    data->ip_header->timeToLive = iph->timeToLive;
    data->ip_header->headerLength = iph->version;
    
    data->ip_header->flags = iph->flags;
    
    
    int iplen = data->ip_header->headerLength * 4; // IPͷ����

    switch (iph->protocol)
    {
    case PROTOCOL_ICMP://icmp
        return analyze_icmp((unsigned char*)packet + iplen, data);
        break;
    case PROTOCOL_TCP://tcp
        return analyze_tcp((unsigned char*)packet + iplen, data);
        break;
    case PROTOCOL_UDP://udp
        return analyze_udp((unsigned char*)packet + iplen, data);
        break;
    default:
        return -1;
        break;
    }
    return 1;
}

int analyze_ip6(const unsigned char* pkt, struct data_save* data)
{
    int i;
    struct IPv6Header* iph6 = (struct IPv6Header*)pkt;
    data->ipv6_header = (struct IPv6Header*)malloc(sizeof(struct IPv6Header));

    if (NULL == data->ipv6_header)
        return -1;

    
    data->ipv6_header->version = iph6->version;
    data->ipv6_header->trafficClass = iph6->trafficClass;
    data->ipv6_header->flowLabel = iph6->flowLabel;
    data->ipv6_header->payloadLength = ntohs(iph6->payloadLength);
    data->ipv6_header->nextHeader = iph6->nextHeader;
    data->ipv6_header->hopLimit = iph6->hopLimit;
    for (i = 0; i < 8; i++)
    {
        data->ipv6_header->sourceAddress[i] = ntohs(iph6->sourceAddress[i]);
        data->ipv6_header->destinationAddress[i] = ntohs(iph6->destinationAddress[i]);
    }
    
    switch (iph6->nextHeader)
    {
    case 0x3a:
        return analyze_icmp6((unsigned char*)iph6 + 40, data);
        break;
    case 0x06:
        return analyze_tcp((unsigned char*)iph6 + 40, data);
        break;
    case 0x11:
        return analyze_udp((unsigned char*)iph6 + 40, data);
        break;
    default:
        return -1;
        break;
    }

    return 1;
}


// �����ݰ���ʮ�����Ʒ�ʽ��ӡ����

void print_packet_hex(const unsigned char* packet, size_t size_packet, CString& buf)
{
    char tempbuf[256] = {}; // ��ʼ����ʱ������
    for (size_t i = 0; i < size_packet; i += 16) // ÿ16�ֽڴ�ӡһ��
    {
        buf.AppendFormat(_T("%04zx:  "), i); // ��ӡʮ������ƫ����
        size_t rowcount = (size_packet - i) > 16 ? 16 : (size_packet - i); // ���㵱ǰ�е��ֽ���
        for (size_t j = 0; j < rowcount; j++) // ��ӡʮ����������
        {
            buf.AppendFormat(_T("%02x  "), packet[i + j]);
        }
        // ����16�ֽڣ��ÿո���
        if (rowcount < 16) {
            // ��ӿո�
            buf.Append(_T("  "));
            // ���ASCII�ַ�
            for (size_t j = 0; j < rowcount; j++) {
                unsigned char ch = packet[i + j];
                ch = isprint(ch) ? ch : '.'; // �Ǵ�ӡ�ַ��滻Ϊ'.'
                buf.AppendFormat(_T("%c"), ch);
            }
            // ��ӻ��з�
            buf.Append(_T("\r\n"));
            return; // ��������
        }
        // ��ӻ��з�
        buf.Append(_T("\r\n"));
    }
}


int analyze_frame(const unsigned char* packet, struct data_save* data)
{
    int i;
    struct EthernetHeader* ethh = (struct EthernetHeader*)packet;

    // ����ռ䲢����Ŀ�ĵ�ַ��Դ��ַ
    data->ethernet_header = (struct EthernetHeader*)malloc(sizeof(struct EthernetHeader));
    if (!data->ethernet_header)
        return -1;

    for (i = 0; i < 6; i++)
    {
        data->ethernet_header->destMac[i] = ethh->destMac[i];
        data->ethernet_header->srcMac[i] = ethh->srcMac[i];
    }

    // ���������ֽ�˳��ԭ����Ҫ�������ֶν���ת��
    data->ethernet_header->etherType = ntohs(ethh->etherType);
    
    // ����֡���ͽ��д���
    switch (data->ethernet_header->etherType)
    {
    case 0x0806: // ARP
        return analyze_arp((unsigned char*)packet + 14, data);  // MACͷ��СΪ14
        break;
    case 0x0800: // IPv4
        return analyze_ip((unsigned char*)packet + 14, data);
        break;
    case 0x86dd: // IPv6
        return analyze_ip6((unsigned char*)packet + 14, data);
        break;
    default:
        return -1;
        break;
    }

    return 1;
}