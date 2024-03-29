
// snifferDlg.h: 头文件
//

#pragma once
#include"pcap.h"
#include "protocolHeader.h"
// CsnifferDlg 对话框
DWORD WINAPI sinff_captureThread(LPVOID lpParameter);
class CsnifferDlg : public CDialogEx
{
// 构造
public:
	CsnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数

//功能函数
	int sniff_init();
	int sniff_start();
	int sniff_detail(int index);
	int sniff_content(int index);
	int sniff_save();
	int sniff_read(CString path);
	int iprecombine(int index);//重组
	int update_detail(data_save* pakeage_T, int len); //展示重组树
	int update_packet(int len, u_char* pkt_data); //展示重组详细
	u_char* combineData(u_char* existingData, int prelen, u_char* newData, int headerLength, int sumlen);
//数据
	char filepath[100];
	char filename[50];
	pcap_dumper_t* dump;
	pcap_if_t* alldevs;
	pcap_if_t* device;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
//线程
	HANDLE threadhandle;
// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	CMenu m_menu;
	int cursor_index = -1;
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CComboBox network;
	CString filter;
	CEdit content;
	CPtrList localData;//本地数据包
	CPtrList networkData;//网络数据包
	void initialMenuBar();
	CBitmapButton bitButton;
	afx_msg void OnCbnSelchangeCombo1();
	afx_msg void OnEnChangeEdit1();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void FileSave();
	afx_msg void FileRead();
	afx_msg void FileExit();
	afx_msg void FileClose();
	afx_msg void OnIpRecombination();				//IP重组
	afx_msg void OnLvnItemchangedList2(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnNMCustomdrawList2(NMHDR* pNMHDR, LRESULT* pResult);
	CButton sniffer_btnstart;
	CButton sniffer_btnstop;
	/*CButton sniffer_btnread;
	CButton sniffer_btnsave;*/
	CListCtrl data_packets;
	CTreeCtrl detail;
	int number=0;
	afx_msg void OnEnChangeEdit2();
};
