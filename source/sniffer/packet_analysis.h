#include "afxcmn.h"
#include "afxwin.h"
#include <malloc.h> 
#include <Winsock2.h>
#include "protocolHeader.h"
#ifndef PACKET_ANALYSIS_H
#define PACKET_ANALYSIS_H

/*��·���*/
int analyze_frame(const u_char* packet, struct data_save* data);

/*������*/
int analyze_ip(const u_char* packet, struct data_save* data);
int analyze_ip6(const u_char* packet, struct data_save* data);
int analyze_arp(const u_char* packet, struct data_save* data);

/*������*/
int analyze_icmp(const u_char* packet, struct data_save* data);
//icmp��Ϊ���⣬ͨ����Ϊ����ip��һ���ݣ�����������Ϊip������Ч��
//�ɵ���ʽ�������д��䣬��tcp��udpһ����������������ڴ����������
int analyze_icmp6(const u_char* packet, struct data_save* data);

int analyze_tcp(const u_char* packet, struct data_save* data);
int analyze_udp(const u_char* packet, struct data_save* data);

/*Ӧ�ò��*/
//int analyze_http(const u_char* packet, struct data_save* data);

/*�����ݰ���ʮ�����Ƶķ�ʽ��ӡ*/
void print_packet_hex(const u_char* packet, size_t size_packet, CString& buf);
#endif