#include "afxcmn.h"
#include "afxwin.h"
#include <malloc.h> 
#include <Winsock2.h>
#include "protocolHeader.h"
#ifndef PACKET_ANALYSIS_H
#define PACKET_ANALYSIS_H

/*链路层包*/
int analyze_frame(const u_char* packet, struct data_save* data);

/*网络层包*/
int analyze_ip(const u_char* packet, struct data_save* data);
int analyze_ip6(const u_char* packet, struct data_save* data);
int analyze_arp(const u_char* packet, struct data_save* data);

/*传输层包*/
int analyze_icmp(const u_char* packet, struct data_save* data);
//icmp较为特殊，通常认为它是ip的一部份，但是它是作为ip包的有效载
//荷的形式在网络中传输，如tcp和udp一样，所以这里把它在传输层来处理
int analyze_icmp6(const u_char* packet, struct data_save* data);

int analyze_tcp(const u_char* packet, struct data_save* data);
int analyze_udp(const u_char* packet, struct data_save* data);

/*应用层包*/
//int analyze_http(const u_char* packet, struct data_save* data);

/*将数据包以十六进制的方式打印*/
void print_packet_hex(const u_char* packet, size_t size_packet, CString& buf);
#endif