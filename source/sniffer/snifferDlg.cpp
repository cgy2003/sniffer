
// snifferDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "sniffer.h"
#include "snifferDlg.h"
#include "afxdialogex.h"
#include"pcap.h"
#include "packet_analysis.h"
#include <cstdlib>


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	
	
	
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CsnifferDlg 对话框



CsnifferDlg::CsnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	
}

void CsnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, network);
	
	DDX_Control(pDX, IDC_TREE1, detail);
	DDX_Control(pDX, IDC_LIST2, data_packets);
	DDX_Control(pDX, IDC_BUTTON1, sniffer_btnstart);
	DDX_Control(pDX, IDC_BUTTON2, sniffer_btnstop);
	/*DDX_Control(pDX, IDC_BUTTON3, sniffer_btnsave);
	DDX_Control(pDX, IDC_BUTTON4, sniffer_btnread);*/
	DDX_Control(pDX, IDC_EDIT1, content);
}

BEGIN_MESSAGE_MAP(CsnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_SELCHANGE(IDC_COMBO1, &CsnifferDlg::OnCbnSelchangeCombo1)
	ON_EN_CHANGE(IDC_EDIT1, &CsnifferDlg::OnEnChangeEdit1)
	ON_BN_CLICKED(IDC_BUTTON1, &CsnifferDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CsnifferDlg::OnBnClickedButton2)
	ON_COMMAND(ID_MENU_FILE_SAVE, &CsnifferDlg::FileSave)
	ON_COMMAND(ID_MENU_FILE_OPEN, &CsnifferDlg::FileRead)
	ON_COMMAND(ID_MENU_FILE_EXIT, &CsnifferDlg::FileExit)
	ON_COMMAND(ID_MENU_FILE_CLOSE, &CsnifferDlg::FileClose)
	ON_COMMAND(ID_IP_RECOMBINATION, &CsnifferDlg::OnIpRecombination)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST2, &CsnifferDlg::OnLvnItemchangedList2)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST2, &CsnifferDlg::OnNMCustomdrawList2)

	ON_EN_CHANGE(IDC_EDIT2, &CsnifferDlg::OnEnChangeEdit2)
END_MESSAGE_MAP()


// CsnifferDlg 消息处理程序

BOOL CsnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	initialMenuBar();
	// TODO: 在此添加额外的初始化代码
	HBITMAP hBmp_1 = ::LoadBitmap(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDB_BITMAP1));
	sniffer_btnstart.SetBitmap(hBmp_1);
	HBITMAP hBmp_2 = ::LoadBitmap(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDB_BITMAP2));
	sniffer_btnstop.SetBitmap(hBmp_2);
	data_packets.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	data_packets.InsertColumn(0, _T("编号"), 3, 30);                        //1表示右，2表示中，3表示左
	data_packets.InsertColumn(1, _T("时间"), 3, 130);
	data_packets.InsertColumn(2, _T("长度"), 3, 72);
	data_packets.InsertColumn(3, _T("源MAC地址"), 3, 140);
	data_packets.InsertColumn(4, _T("目的MAC地址"), 3, 140);
	data_packets.InsertColumn(5, _T("协议"), 3, 70);
	data_packets.InsertColumn(6, _T("源IP地址"), 3, 145);
	data_packets.InsertColumn(7, _T("目的IP地址"), 3, 145);

	network.AddString(_T("请选择一个网卡接口(必选)"));
	

	if (sniff_init() < 0)
		return FALSE;

	/*初始化接口列表*/
	for (device = alldevs; device; device = device->next)
	{
		if (device->description)
			network.AddString(CString(device->description)); 
	}

	

	network.SetCurSel(0);
	

	sniffer_btnstop.EnableWindow(FALSE);
	/*sniffer_btnsave.EnableWindow(FALSE);*/
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CsnifferDlg::initialMenuBar()
{
	m_menu.LoadMenu(IDR_MENU1);
	SetMenu(&m_menu);

	/* 菜单项禁用 */
//	CMenu* pMenu = this->GetMenu();
	if (m_menu)
	{
		m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_GRAYED);	// 禁用菜单项"关闭"
		m_menu.EnableMenuItem(ID_MENU_FILE_SAVE, MF_GRAYED);	// 禁用菜单项"另存为"
	}
}
void CsnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CsnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CsnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CsnifferDlg::OnCbnSelchangeCombo1()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CsnifferDlg::OnEnChangeEdit1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}

//开始按钮
void CsnifferDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	//如果已经有数据了，提示保存数据
	if (this->localData.IsEmpty() == FALSE)
	{
		if (MessageBox(_T("确认不保存数据？"), _T("警告"), MB_YESNO) == IDNO)
		{
			this->sniff_save();
		}
	}

													
	this->localData.RemoveAll();				
	this->networkData.RemoveAll();
	
	if (this->sniff_start() < 0)
		return;
	this->data_packets.DeleteAllItems();
	this->detail.DeleteAllItems();
	this->content.SetWindowTextW(_T(""));
	this->sniffer_btnstart.EnableWindow(FALSE);
	this->sniffer_btnstop.EnableWindow(TRUE);
	/*this->sniffer_btnsave.EnableWindow(FALSE);*/
}

//结束按钮
void CsnifferDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	if (this->threadhandle != NULL)
	{
		if (TerminateThread(this->threadhandle, -1) == 0)
		{
			MessageBox(_T("关闭线程错误，请稍后重试"));
			return;
		}
		this->threadhandle = NULL;
		this->sniffer_btnstart.EnableWindow(TRUE);
		this->sniffer_btnstop.EnableWindow(FALSE);
		m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_ENABLED);	// 启用菜单项"关闭"
		m_menu.EnableMenuItem(ID_MENU_FILE_SAVE, MF_ENABLED);	// 启用菜单项"保存"
		
	}
}

//保存按钮
void CsnifferDlg::FileSave()
{
	// TODO: 在此添加控件通知处理程序代码
	if (this->sniff_save() < 0)
		return;
}

//读取按钮
void CsnifferDlg::FileRead()
{
	// TODO: 在此添加控件通知处理程序代码
	//读取之前将数据包列表清空
	this->data_packets.DeleteAllItems();							
	this->localData.RemoveAll();				
	this->networkData.RemoveAll();
	

	//打开文件对话框
	CFileDialog   FileDlg(TRUE, _T(".pcap"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT);
	FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");
	if (FileDlg.DoModal() == IDOK)
	{
		int ret = this->sniff_read(FileDlg.GetPathName());
		if (ret < 0)
			return;
	}
	if (m_menu)
	{
		m_menu.EnableMenuItem(ID_MENU_FILE_OPEN, MF_ENABLED);	// 启用菜单项"打开"
		m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_ENABLED);	// 启用菜单项"关闭"
		m_menu.EnableMenuItem(ID_MENU_FILE_SAVE, MF_ENABLED);	// 启用菜单项"保存"
	}
}
void CsnifferDlg::FileClose()
{
	this->data_packets.DeleteAllItems();
	this->detail.DeleteAllItems();
	this->content.SetWindowTextW(_T(""));
	this->number = 0;
	this->localData.RemoveAll();
	this->networkData.RemoveAll();
	
	m_menu.EnableMenuItem(ID_MENU_FILE_CLOSE, MF_GRAYED);	// 禁用菜单项"关闭"
	m_menu.EnableMenuItem(ID_MENU_FILE_SAVE, MF_GRAYED);	// 禁用菜单项"保存"
	
}

//退出程序
void CsnifferDlg::FileExit()
{
	exit(0);
}

//重组入口
void CsnifferDlg::OnIpRecombination()
{
	int index = cursor_index;
	if (index >= this->localData.GetCount() || index == -1)
		return;
	this->iprecombine(index);
}

// 在给定数据链表中寻找第一个满足特定条件的数据包
// 参数:
//   tmp: 指向数据链表中的当前数据包的指针
//   index: 当前数据包的索引
//   lpParameter: 指向参数的指针
// 返回值:
//   指向满足条件的第一个数据包的指针，若未找到则返回空指针
struct data_save* FindFstIp(struct data_save* tmp, int& index, LPVOID lpParameter) {
	struct data_save* first = NULL; // 初始化第一个满足条件的数据包指针为NULL
	CsnifferDlg* bpthis = (CsnifferDlg*)lpParameter; // 将参数转换为相应的类指针

	// 获取当前数据包的标志位和偏移量
	int flag = (tmp->ip_header->flags & 0b11100000) >> 5;
	int offset = ((((tmp->ip_header->flags) & 0b11111) << 8) + (((tmp->ip_header->flags) >> 8) & 0xff)) << 3;

	// 定义用于更新标志位和偏移量的函数
	auto updateFlagOffset = [&]() {
		flag = (tmp->ip_header->flags & 0b11100000) >> 5;
		offset = ((((tmp->ip_header->flags) & 0b11111) << 8) + (((tmp->ip_header->flags) >> 8) & 0xff)) << 3;
		};

	// 检查当前数据包是否满足条件
	if (flag == 1 && offset == 0) {
		first = tmp; // 若满足条件，则将第一个满足条件的数据包指针指向当前数据包
	}
	else {
		POSITION localpos;

		// 循环直到找到满足条件的数据包或者遍历完整个链表
		while (!(flag == 1 && offset == 0)) {
			index--;
			localpos = bpthis->localData.FindIndex(index);
			struct data_save* tmp1 = (struct data_save*)(bpthis->localData.GetAt(localpos));

			// 检查当前数据包是否满足特定的识别条件
			if (tmp1->ip_header != NULL && tmp1->ip_header->identification == tmp->ip_header->identification) {
				tmp = tmp1;
				updateFlagOffset(); // 更新标志位和偏移量
			}

			// 若已经回溯到链表头部但仍未找到满足条件的数据包，则返回空指针
			if (bpthis->localData.GetHead() == tmp1 && !(flag == 1 && offset == 0)) {
				return NULL;
			}
		}
		first = tmp; // 将第一个满足条件的数据包指针指向当前数据包
	}

	return first; // 返回指向第一个满足条件的数据包的指针，若未找到则返回空指针
}
//重组
int CsnifferDlg::iprecombine(int index)
{
	// 查找本地数据中指定索引的位置
	POSITION localpos = this->localData.FindIndex(index);
	// 获取数据包结构体指针
	struct data_save* package_T = (struct data_save*)(this->localData.GetAt(localpos));
	POSITION netpos;
	u_char* pkt_data;
	int i = 0;

	// 如果数据包不是IPv4包，弹出消息框并返回
	if (package_T->ip_header == NULL)
	{
		MessageBox(_T("该数据包不是个IPv4包。。。"));
		return 0;
	}

	// 提取标志位和偏移量
	int flag = (package_T->ip_header->flags & 0b11100000) >> 5;
	int offset = ((((package_T->ip_header->flags) & 0b11111) << 8) + (((package_T->ip_header->flags) >> 8) & 0xff)) << 3;

	// 处理不可分段的IP包
	if (flag == 0b010)
	{
		MessageBox(_T("该IP包为不可分段IP包"));
		return 0;
	}
	// 处理可分段但未实际分段的IP包
	else if (flag == 0 && offset == 0)
	{
		MessageBox(_T("该IP包可分段，但是实际没有分段"));
		return 0;
	}
	else
	{
		// 找到第一个IP包以及其索引
		struct data_save* first;
		if ((first = FindFstIp(package_T, index, this)) == NULL)
		{
			MessageBox(_T("重组失败，有可能是由于没抓全包"));
			return 0;
		}

		// 初始化标志位和偏移量
		flag = 1;
		offset = 0;

		// 在网络数据中查找指定索引的位置
		netpos = this->networkData.FindIndex(index);
		// 获取网络数据
		pkt_data = (u_char*)this->networkData.GetAt(netpos);

		// 存储重组包规则结构体（第一个包的结构体）
		struct data_save* res = first;
		// 存储最后data的字符数组
		u_char* res_data;
		u_char* tmp = NULL; // 初始化为NULL或者分配内存
		int prelen = 0, sumlen = 0;

		// 拼接第一个包
		res_data = (u_char*)malloc(first->len);
		if (res_data)
			memcpy(res_data, pkt_data, first->len);

		sumlen = first->len;

		// 如果找到了同id && 最后一个分段 && 退出
		while (!(flag == 0 && offset != 0 && res->ip_header->identification == first->ip_header->identification)) {
			index++;
			localpos = this->localData.FindIndex(index);
			first = (struct data_save*)this->localData.GetAt(localpos);

			// 同identification需要合并
			if (first->ip_header != nullptr && first->ip_header->identification == res->ip_header->identification) {
				flag = (first->ip_header->flags & 0b11100000) >> 5;
				offset = ((((first->ip_header->flags) & 0b11111) << 8) + (((first->ip_header->flags) >> 8) & 0xff)) << 3;

				// 更新长度
				prelen = sumlen;
				sumlen += (first->ip_header->totalLength - first->ip_header->headerLength * 4);

				// 获取数据
				netpos = this->networkData.FindIndex(index);
				pkt_data = (u_char*)this->networkData.GetAt(netpos);

				// 追加数据
				if (auto tmp = combineData(res_data, prelen, pkt_data, first->ip_header->headerLength, sumlen)) {
					free(res_data);
					res_data = tmp;
				}
			}
			// 不同identification 直接放过
		}

		// 新的ip包长度 = 包总长 - 14
		if (res_data) {
			int iplen = sumlen - 14;
			_itoa(iplen, reinterpret_cast<char*>(res_data + 14 + 2), 10);
			memset(res_data + 14 + 10, 0, 2);
		}

		update_detail(res, sumlen - 14);
		update_packet(sumlen, res_data);

		return 1;
	}
}
u_char* CsnifferDlg::combineData(u_char * existingData, int prelen, u_char * newData, int headerLength, int sumlen) {
		auto tmp = static_cast<u_char*>(malloc(sumlen));
		if (tmp) {
			memcpy(tmp, existingData, prelen);
			memcpy(tmp + prelen, newData + 14 + headerLength * 4, static_cast<size_t>(sumlen) - prelen);
		}
		return tmp;
}




// 递归展开树的所有节点
void ExpandAllItems(CTreeCtrl& treeCtrl, HTREEITEM hItem)
{
	if (hItem == NULL)
		return;

	// 展开当前节点
	treeCtrl.Expand(hItem, TVE_EXPAND);

	// 递归展开子节点
	HTREEITEM hChildItem = treeCtrl.GetChildItem(hItem);
	while (hChildItem != NULL)
	{
		ExpandAllItems(treeCtrl, hChildItem);
		hChildItem = treeCtrl.GetNextItem(hChildItem, TVGN_NEXT);
	}
}

int CsnifferDlg::update_detail(data_save* local_data, int len) //展示重组树
{
	int i;
	/* 清空树 */
	this->detail.DeleteAllItems();
	/* 初始化 */
	CString str;
	/* 树根 */
	str.Format(_T("重组包：包类型为:") + CString(local_data->save_type));
	HTREEITEM root = this->detail.GetRootItem();
	HTREEITEM data = this->detail.InsertItem(str, root);
	/* dl层 */
	HTREEITEM frame = this->detail.InsertItem(_T("链路层数据："), data);
	str.Empty();
	//源MAC
	str.Format(_T("源MAC："));
	for (i = 0; i < 5; i++)
	{
		str.AppendFormat(_T("%02x-"), local_data->ethernet_header->srcMac[i]);
	}
	str.AppendFormat(_T("%02x"), local_data->ethernet_header->srcMac[i]);
	this->detail.InsertItem(str, frame);
	//目的MAC
	str.Format(_T("目的MAC："));
	for (i = 0; i < 5; i++)
	{
		str.AppendFormat(_T("%02x-"), local_data->ethernet_header->destMac[i]);
	}
	str.AppendFormat(_T("%02x"), local_data->ethernet_header->destMac[i]);
	this->detail.InsertItem(str, frame);
	//类型
	str.Format(_T("类型：0x%04x"), local_data->ethernet_header->etherType);
	this->detail.InsertItem(str, frame);


	/* ip层 */

	HTREEITEM ip = this->detail.InsertItem(_T("IP协议头"), data);

	str.Format(_T("版本：%d"), local_data->ip_header->version);
	this->detail.InsertItem(str, ip);
	str.Format(_T("首部长度：%d*4字节"), local_data->ip_header->headerLength);
	this->detail.InsertItem(str, ip);
	str.Format(_T("服务类型：%d"), local_data->ip_header->typeOfService);
	this->detail.InsertItem(str, ip);
	str.Format(_T("总长度：%d字节"), len);
	this->detail.InsertItem(str, ip);
	str.Format(_T("标识：0x%02x"), local_data->ip_header->identification);
	this->detail.InsertItem(str, ip);
	int mask_frag = 0b11100000;
	str.Format(_T("标志位：0x%01x"), (local_data->ip_header->flags & mask_frag) >> 5);

	HTREEITEM ipFlag = this->detail.InsertItem(str, ip);
	str.Format(_T("RSV：%d"), ((ntohs(local_data->ip_header->flags) >> 15) & 0x0001));
	this->detail.InsertItem(str, ipFlag);
	str.Format(_T("DF：%d"), ((ntohs(local_data->ip_header->flags) >> 14) & 0x0001));
	this->detail.InsertItem(str, ipFlag);
	str.Format(_T("MF：%d"), ((ntohs(local_data->ip_header->flags) >> 13) & 0x0001));
	this->detail.InsertItem(str, ipFlag);
	str.Format(_T("段偏移：%d"),
		((((local_data->ip_header->flags) & 0b11111) << 8) + (((local_data->ip_header->flags) >> 8) & 0xff)) << 3);
	this->detail.InsertItem(str, ip);
	str.Format(_T("生存时间：%d"), local_data->ip_header->timeToLive);
	this->detail.InsertItem(str, ip);
	str.Format(_T("协议：%d"), local_data->ip_header->protocol);
	this->detail.InsertItem(str, ip);
	str.Format(_T("头部校验和：0x%04x"), local_data->ip_header->headerChecksum);
	this->detail.InsertItem(str, ip);

	str.Format(_T("发送方IP："));
	for (i = 0; i < 3; i++)
	{
		str.AppendFormat(_T("%d."), local_data->ip_header->sourceIpAddress[i]);
	}
	str.AppendFormat(_T("%d"), local_data->ip_header->sourceIpAddress[i]);
	this->detail.InsertItem(str, ip);

	str.Format(_T("接收方IP："));
	for (i = 0; i < 3; i++)
	{
		str.AppendFormat(_T("%d."), local_data->ip_header->destinationIpAddress[i]);
	}
	str.AppendFormat(_T("%d"), local_data->ip_header->destinationIpAddress[i]);
	this->detail.InsertItem(str, ip);


	if (local_data->ip_header->protocol == 1)							//ICMP
	{
		HTREEITEM icmp = this->detail.InsertItem(_T("ICMP协议头"), data);

		str.Format(_T("类型:%d"), local_data->icmp_header->type);
		this->detail.InsertItem(str, icmp);
		str.Format(_T("代码:%d"), local_data->icmp_header->code);
		this->detail.InsertItem(str, icmp);
		str.Format(_T("序列号:%d"), local_data->icmp_header->seq);
		this->detail.InsertItem(str, icmp);
		str.Format(_T("校验和:%d"), local_data->icmp_header->checksum);
		this->detail.InsertItem(str, icmp);

	}
	else if (local_data->ip_header->protocol == 6) {				//TCP

		HTREEITEM tcp = this->detail.InsertItem(_T("TCP协议头"), data);

		str.Format(_T("  源端口:%d"), local_data->tcp_header->sourcePort);
		this->detail.InsertItem(str, tcp);
		str.Format(_T("  目的端口:%d"), local_data->tcp_header->destPort);
		this->detail.InsertItem(str, tcp);
		str.Format(_T("  序列号:0x%04x"), local_data->tcp_header->sequenceNumber);
		this->detail.InsertItem(str, tcp);
		str.Format(_T("  确认号:0x%04x"), local_data->tcp_header->ackNumber);
		this->detail.InsertItem(str, tcp);
		str.Format(_T("  头部长度:%d*4字节"), local_data->tcp_header->dataOffset);
		this->detail.InsertItem(str, tcp);
		HTREEITEM flag = this->detail.InsertItem(_T(" +标志位"), tcp);
		str.Format(_T("CWR %d"), local_data->tcp_header->cwr);
		this->detail.InsertItem(str, flag);
		str.Format(_T("ECE %d"), local_data->tcp_header->ece);
		this->detail.InsertItem(str, flag);
		str.Format(_T("URG %d"), local_data->tcp_header->urg);
		this->detail.InsertItem(str, flag);
		str.Format(_T("ACK %d"), local_data->tcp_header->ack);
		this->detail.InsertItem(str, flag);
		str.Format(_T("PSH %d"), local_data->tcp_header->psh);
		this->detail.InsertItem(str, flag);
		str.Format(_T("RST %d"), local_data->tcp_header->rst);
		this->detail.InsertItem(str, flag);
		str.Format(_T("SYN %d"), local_data->tcp_header->syn);
		this->detail.InsertItem(str, flag);
		str.Format(_T("FIN %d"), local_data->tcp_header->fin);
		this->detail.InsertItem(str, flag);

		str.Format(_T("  窗口大小:%d"), local_data->tcp_header->window);
		this->detail.InsertItem(str, tcp);
		str.Format(_T("  校验和:0x%04x"), local_data->tcp_header->checksum);
		this->detail.InsertItem(str, tcp);
		str.Format(_T("  紧急指针:%d"), local_data->tcp_header->urgentPointer);
		this->detail.InsertItem(str, tcp);

		//str.Format(_T("  选项:%d"), local_data->tcp_header->opt);
		//this->detail.InsertItem(str, tcp);
	}
	else if (local_data->ip_header->protocol == 17) {				//UDP
		HTREEITEM udp = this->detail.InsertItem(_T("UDP协议头"), data);

		str.Format(_T("源端口:%d"), local_data->udp_header->sourcePort);
		this->detail.InsertItem(str, udp);
		str.Format(_T("目的端口:%d"), local_data->udp_header->destPort);
		this->detail.InsertItem(str, udp);
		str.Format(_T("总长度:%d"), local_data->udp_header->length);
		this->detail.InsertItem(str, udp);
		str.Format(_T("校验和:0x%02x"), local_data->udp_header->checksum);
		this->detail.InsertItem(str, udp);
	}
	else {
		HTREEITEM other = this->detail.InsertItem(_T("IP上层非常见协议："), data);
		str.Format(_T("协议号：%d"), local_data->ip_header->protocol);
		this->detail.InsertItem(str, other);
	}
	// 找到树的根节点
	HTREEITEM rootItem = this->detail.GetRootItem();

	// 调用递归展开函数
	ExpandAllItems(this->detail, rootItem);

	return 1;
}


int CsnifferDlg::update_packet(int len, u_char* pkt_data) //展示重组详细
{
	CString buf;
	print_packet_hex(pkt_data, len, buf);
	this->content.SetWindowText(buf); //自适应编码
	return 1;
}
void CsnifferDlg::OnLvnItemchangedList2(NMHDR* pNMHDR, LRESULT* pResult)
{
	// 将消息头转换为列表视图通知结构体
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);

	// 获取当前选中项的索引
	int index;
	index = this->data_packets.GetHotItem();

	// 检查索引是否在合法范围内，避免越界访问
	if (index > this->localData.GetCount() - 1)
		return;

	cursor_index = index;
	// 调用函数更新显示选中项的本地数据的十六进制表示
	this->sniff_content(index);

	// 调用函数更新显示选中项的相关信息
	this->sniff_detail(index);

	// 设置消息处理的结果为 0，表示消息已经被处理
	*pResult = 0;
}
// 改变ListCtrl每行颜色的消息处理函数
void CsnifferDlg::OnNMCustomdrawList2(NMHDR* pNMHDR, LRESULT* pResult)
{
	// 将消息头转换为列表视图自定义绘制结构体
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;

	// 设置消息处理结果为 0
	*pResult = 0;

	// 处理绘制阶段
	if (CDDS_PREPAINT == pNMCD->nmcd.dwDrawStage)
	{
		// 通知进行项绘制
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (CDDS_ITEMPREPAINT == pNMCD->nmcd.dwDrawStage)
	{
		// 获取当前项在列表中的位置
		POSITION pos = this->localData.FindIndex(pNMCD->nmcd.dwItemSpec);

		// 获取与该项相关的本地数据
		struct data_save* local_data = (struct data_save*)this->localData.GetAt(pos);

		// 根据数据类型设置文本背景颜色
		COLORREF crText= RGB(111, 224, 254);
		char buf[10];
		memset(buf, 0, 10);
		strcpy(buf, local_data->save_type);

		if (strcmp(buf, "IPV6") == 0)
			crText = RGB(176, 48, 96);  // Dark Rose
		else if (strcmp(buf, "UDP") == 0)
			crText = RGB(0, 128, 0);  // Forest Green
		else if (strcmp(buf, "TCP") == 0)
			crText = RGB(111, 224, 254);  // Dark Red
		else if (strcmp(buf, "ARP") == 0)
			crText = RGB(255, 215, 0);  // Gold
		else if (strcmp(buf, "ICMP") == 0)
			crText = RGB(255, 255, 192);  // Navy Blue
		else if (strcmp(buf, "HTTP") == 0)
			crText = RGB(255, 140, 0);  // Dark Orange
		else if (strcmp(buf, "ICMPv6") == 0)
			crText = RGB(205, 92, 92);  // Indian Red
		else if (strcmp(buf, "HTTPS") == 0)
			crText = RGB(100, 149, 237);  // Cornflower Blue
		else if (strcmp(buf, "FTP") == 0)
			crText = RGB(70, 130, 180);  // Steel Blue
		else if (strcmp(buf, "DNS") == 0)
			crText = RGB(85, 107, 47);  // Dark Olive Green
		else if (strcmp(buf, "TELNET") == 0)
			crText = RGB(255, 69, 0);  // Orange Red
		else if (strcmp(buf, "DHCP") == 0)
			crText = RGB(0, 0, 205);  // Medium Blue



		// 设置文本背景颜色
		pNMCD->clrTextBk = crText;

		// 通知执行默认的绘制操作
		*pResult = CDRF_DODEFAULT;
	}
}


//功能函数
int CsnifferDlg::sniff_init()
{
	// 查找可用的网络设备
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		AfxMessageBox(_T("Error in pcap_findalldevs: ") + CString(errbuf));
		return -1; // 返回非0值表示失败
	}

	
	if (alldevs == NULL) {
		AfxMessageBox(_T("No devices found. Make sure WinPcap is installed."));
		return -1;
	}
	
	return 0;
}

int CsnifferDlg::sniff_start() {
	number = 1;
	struct bpf_program fcode;
	bpf_u_int32 netmask = 0xffffff; // 假设网络掩码
	char* device_name = NULL;
	sniff_init();
	device = alldevs;
	int network_index = this->network.GetCurSel();
	GetDlgItem(IDC_EDIT2)->GetWindowTextW(this->filter);
	
	if (network_index == 0 || network_index == CB_ERR)
	{
		MessageBox(_T("Please select a suitable network interface"));
		return -1;
	}
	
	//选取网卡
	for (int i = 0; i < network_index - 1; i++)
		device = device->next;
	// 检查是否成功选取了一个设备
	if (device == NULL) {
		AfxMessageBox(_T("Selected network interface is not available."));
		pcap_freealldevs(alldevs);
		return -1;
	}

	// 打开网络接口
	 handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
	if (handle == NULL) {
		AfxMessageBox(_T("Could not open the selected interface: ") + CString(errbuf));
		pcap_freealldevs(alldevs);
		return -1;
	}
	char* str = nullptr; // 声明 filter 指针，初始化为 nullptr

	int len = this->filter.GetLength() + 1;
	if (len==0) {
		str = nullptr; // 不需要过滤器，设为 nullptr
	}
	else {
		
		str = (char*)malloc(len);

		for (int x = 0; x < len; x++) {
			str[x] = this->filter.GetAt(x);
		}
	}

	if (pcap_compile(handle, &fcode, str, 1, netmask) < 0)
	{
		MessageBox(_T("编译器规则错误，请重新输入后再次确认"));
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_setfilter(handle, &fcode) < 0)
	{
		MessageBox(_T("编译器编译通过但设置出错"));
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (str) {
		free(str);
	}

	// 设置过滤器
	if (pcap_setfilter(handle, &fcode) < 0) {
		MessageBox(_T("Error setting the filter"));
		pcap_freealldevs(alldevs);
		return -1;
	}

	CFileFind file;
	char thistime[30];
	struct tm ltime;
	memset(filepath, 0, 100);
	memset(filename, 0, 50);

	if (!file.FindFile(_T("SavedData")))
	{
		CreateDirectory(_T("SavedData"), NULL);
	}

	// 获取当前时间
	time_t nowtime;
	time(&nowtime);
	localtime_s(&ltime,&nowtime);

	// 格式化时间字符串
	strftime(thistime, sizeof(thistime), "%Y%m%d %H%M%S", &ltime);

	// 构建文件路径和文件名
	strcpy(filepath, "SavedData\\");
	strcat(filename, thistime);
	strcat(filename, ".pcap");

	strcat(filepath, filename);
	dump = pcap_dump_open(handle, filepath);
	if (dump == NULL)
	{
		MessageBox(_T("文件创建错误！"));
		return -1;
	}

	pcap_freealldevs(alldevs);
	/*接收数据，新建线程处理*/
	LPDWORD threadCap = NULL;
	threadhandle = CreateThread(NULL, 0, sinff_captureThread, this, 0, threadCap);
	if (threadhandle == NULL)
	{
		int code = GetLastError();
		CString str;
		str.Format(_T("创建线程错误，代码为%d."), code);
		MessageBox(str);
		return -1;
	}
	return 1;
}

DWORD WINAPI sinff_captureThread(LPVOID lpParameter)
{
	
	int res, nItem;
	struct tm* ltime;
	CString timestr, buf, srcMacMac, destMacMac;
	time_t local_tv_sec;
	struct pcap_pkthdr* header;        // 数据包头
	const u_char* pkt_data = NULL, * pData = NULL;   // 网络中收到的字节流数据
	u_char* ppkt_data;
	CsnifferDlg* pthis = (CsnifferDlg*)lpParameter;

	// 检查线程句柄
	if (NULL == pthis->threadhandle)
	{
		MessageBox(NULL, _T("线程句柄错误"), _T("提示"), MB_OK);
		return -1;
	}

	// 循环捕获网络数据包
	while ((res = pcap_next_ex(pthis->handle, &header, &pkt_data)) >= 0)
	{
		// 超时，继续等待下一个数据包
		if (res == 0)
			continue;

		// 分配空间并初始化data_save结构体
		struct data_save* data = (struct data_save*)malloc(sizeof(struct data_save));
		memset(data, 0, sizeof(struct data_save));

		// 空间分配失败处理
		if (NULL == data)
		{
			MessageBox(NULL, _T("空间已满，无法接收新的数据包"), _T("Error"), MB_OK);
			return -1;
		}

		// 分析数据包，如果出错或数据包不在处理范围内，继续下一个
		if (analyze_frame(pkt_data, data) < 0)
		{
			free(data); // 释放分配的空间
			continue;
		}

		// 将数据包保存到打开的文件中
		if (pthis->dump != NULL)
		{
			pcap_dump((unsigned char*)pthis->dump, header, pkt_data);
		}

		// 将本地化后的数据装入一个链表中，以便后来使用
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data, pkt_data, header->len);
		pthis->localData.AddTail(data);
		pthis->networkData.AddTail(ppkt_data);


		//下面是对data的可视化显示

		/*预处理，获得时间、长度*/
		data->len = header->len;                // 链路中收到的数据长度
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year + 1900;
		data->time[1] = ltime->tm_mon + 1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

			/*为新接收到的数据包在listControl中新建一个item*/
			buf.Format(_T("%d"), pthis->number);
			nItem = pthis->data_packets.InsertItem(pthis->number, buf);

			/*显示时间戳*/
			timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
				data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
			pthis->data_packets.SetItemText(nItem, 1, timestr);
			//pthis->data_packets.setitem

			/*显示长度*/
			buf.Empty();
			buf.Format(_T("%d"), data->len);
			pthis->data_packets.SetItemText(nItem, 2, buf);

			/*显示源MAC*/
			buf.Empty();
			buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethernet_header->srcMac[0], data->ethernet_header->srcMac[1],
				data->ethernet_header->srcMac[2], data->ethernet_header->srcMac[3], data->ethernet_header->srcMac[4], data->ethernet_header->srcMac[5]);
			pthis->data_packets.SetItemText(nItem, 3, buf);

			/*显示目的MAC*/
			buf.Empty();
			buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethernet_header->destMac[0], data->ethernet_header->destMac[1],
				data->ethernet_header->destMac[2], data->ethernet_header->destMac[3], data->ethernet_header->destMac[4], data->ethernet_header->destMac[5]);
			pthis->data_packets.SetItemText(nItem, 4, buf);

			/*获得协议*/
			pthis->data_packets.SetItemText(nItem, 5, CString(data->save_type));

			/*获得源IP*/
			buf.Empty();
			if (0x0806 == data->ethernet_header->etherType)
			{
				buf.Format(_T("%d.%d.%d.%d"), data->arp_header->senderProtocolAddr[0],
					data->arp_header->senderProtocolAddr[1], 
					data->arp_header->senderProtocolAddr[2], 
					data->arp_header->senderProtocolAddr[3]);
			}
			else if (0x0800 == data->ethernet_header->etherType) {
				buf.Format(_T("%d.%d.%d.%d"), data->ip_header->sourceIpAddress[0],
					data->ip_header->sourceIpAddress[1],
					data->ip_header->sourceIpAddress[2],
					data->ip_header->sourceIpAddress[3]
				);
			}
			else if (0x86dd == data->ethernet_header->etherType) {
				int n;
				for (n = 0; n < 7; n++)
				{
					buf.AppendFormat(_T("%02x:"), data->ipv6_header->sourceAddress[n]);
				}
				buf.AppendFormat(_T("%02x"), data->ipv6_header->sourceAddress[7]);
			}
			pthis->data_packets.SetItemText(nItem, 6, buf);

			/*获得目的IP*/
			buf.Empty();
			if (0x0806 == data->ethernet_header->etherType)
			{
				buf.Format(_T("%d.%d.%d.%d"), data->arp_header->targetProtocolAddr[0],
					data->arp_header->targetProtocolAddr[1], 
					data->arp_header->targetProtocolAddr[2], 
					data->arp_header->targetProtocolAddr[3]);
			}
			else if (0x0800 == data->ethernet_header->etherType) {
				buf.Format(_T("%d.%d.%d.%d"), data->ip_header->destinationIpAddress[0],
					data->ip_header->destinationIpAddress[1],
					data->ip_header->destinationIpAddress[2],
					data->ip_header->destinationIpAddress[3]);
			}
			else if (0x86dd == data->ethernet_header->etherType) {
				int n;
				for (n = 0; n < 8; n++)
				{
						buf.AppendFormat(_T("%02x:"), data->ipv6_header->destinationAddress[n]);
				}
				buf.AppendFormat(_T("%02x"), data->ipv6_header->destinationAddress[7]);
			}
				
				pthis->data_packets.SetItemText(nItem, 7, buf);
				pthis->number++;
		}
		return 1;
	
	
}
int CsnifferDlg::sniff_detail(int index)
{
	POSITION localpos;
	CString str;
	int i;

	this->detail.DeleteAllItems();

	localpos = this->localData.FindIndex(index);
	struct data_save* local_data = (struct data_save*)(this->localData.GetAt(localpos));

	HTREEITEM root = this->detail.GetRootItem();
	str.Format(_T("接收到的第%d个数据包"), index + 1);
	HTREEITEM data = this->detail.InsertItem(str, root);

	/*处理帧数据*/
	HTREEITEM frame = this->detail.InsertItem(_T("链路层数据"), data);
	//源MAC
	str.Format(_T("源MAC："));
	for (i = 0; i < 5; i++)
	{
		str.AppendFormat(_T("%02x-"), local_data->ethernet_header->srcMac[i]);
	}
	str.AppendFormat(_T("%02x"), local_data->ethernet_header->srcMac[i]);
	this->detail.InsertItem(str, frame);
	//目的MAC
	str.Format(_T("目的MAC："));
	for (i = 0; i < 5; i++)
	{
		str.AppendFormat(_T("%02x-"), local_data->ethernet_header->destMac[i]);
	}
	str.AppendFormat(_T("%02x"), local_data->ethernet_header->destMac[i]);
	this->detail.InsertItem(str, frame);
	//类型
	str.Format(_T("类型：0x%04x"), local_data->ethernet_header->etherType);
	this->detail.InsertItem(str, frame);

	//arp
	if (local_data->ethernet_header->etherType==0x0806)							
	{
		HTREEITEM arp = this->detail.InsertItem(_T("ARP协议头"), data);
		str.Format(_T("硬件类型：%d"), local_data->arp_header->hardwareType);
		this->detail.InsertItem(str, arp);
		str.Format(_T("协议类型：0x%02x"), local_data->arp_header->protocolType);
		this->detail.InsertItem(str, arp);
		str.Format(_T("硬件地址长度：%d"), local_data->arp_header->hardwareAddrLen);
		this->detail.InsertItem(str, arp);
		str.Format(_T("协议地址长度：%d"), local_data->arp_header->protocolAddrLen);
		this->detail.InsertItem(str, arp);
		str.Format(_T("操作码：%d"), local_data->arp_header->operation);
		this->detail.InsertItem(str, arp);

		str.Format(_T("发送方MAC："));
		for (i = 0; i < 6; i++)
		{
			str.AppendFormat(_T("%02x-"), local_data->arp_header->senderHardwareAddr[i]);
		}
		str.AppendFormat(_T("%02x"), local_data->arp_header->senderHardwareAddr[i]);
		this->detail.InsertItem(str, arp);

		str.Format(_T("发送方IP："));
		for (i = 0; i < 3; i++)
		{
				str.AppendFormat(_T("%d."), local_data->arp_header->senderProtocolAddr[i]);
		}
		str.AppendFormat(_T("%d"), local_data->arp_header->senderProtocolAddr[i]);
		this->detail.InsertItem(str, arp);

		str.Format(_T("接收方MAC："));
		for (i = 0; i < 5; i++)
		{
				str.AppendFormat(_T("%02x-"), local_data->arp_header->targetHardwareAddr[i]);
		}
		str.AppendFormat(_T("%02x"), local_data->arp_header->targetHardwareAddr[i]);
		this->detail.InsertItem(str, arp);

		str.Format(_T("接收方IP："));
		for (i = 0; i < 3; i++)
		{
			str.AppendFormat(_T("%d."), local_data->arp_header->targetProtocolAddr[i]);
		}
		str.AppendFormat(_T("%d"), local_data->arp_header->targetProtocolAddr[i]);
		this->detail.InsertItem(str, arp);

	}
	else if (local_data->ethernet_header->etherType==0x0800) {					//IP

		HTREEITEM ip = this->detail.InsertItem(_T("IP协议头"), data);

		str.Format(_T("版本：%d"), local_data->ip_header->version);
		this->detail.InsertItem(str, ip);
		str.Format(_T("首部长度：%d*4字节"), local_data->ip_header->headerLength);
		this->detail.InsertItem(str, ip);
		str.Format(_T("服务类型：%d"), local_data->ip_header->typeOfService);
		this->detail.InsertItem(str, ip);
		str.Format(_T("总长度：%d字节"), local_data->ip_header->totalLength);
		this->detail.InsertItem(str, ip);
		str.Format(_T("标识：0x%02x"), local_data->ip_header->identification);
		this->detail.InsertItem(str, ip);
		int mask_frag = 0b11100000;
		str.Format(_T("标志位：0x%01x"), (local_data->ip_header->flags&mask_frag)>>5);
		
		HTREEITEM ipFlag = this->detail.InsertItem(str, ip);
		str.Format(_T("RSV：%d"), ((ntohs(local_data->ip_header->flags) >> 15) & 0x0001));
		this->detail.InsertItem(str, ipFlag);
		str.Format(_T("DF：%d"), ((ntohs(local_data->ip_header->flags) >> 14) & 0x0001));
		this->detail.InsertItem(str, ipFlag);
		str.Format(_T("MF：%d"), ((ntohs(local_data->ip_header->flags) >> 13) & 0x0001));
		this->detail.InsertItem(str, ipFlag);
		str.Format(_T("段偏移：%d"), 
			((((local_data->ip_header->flags) & 0b11111) << 8) + (((local_data->ip_header->flags) >> 8) & 0xff)) << 3);
		this->detail.InsertItem(str, ip);
		str.Format(_T("生存时间：%d"), local_data->ip_header->timeToLive);
		this->detail.InsertItem(str, ip);
		str.Format(_T("协议：%d"), local_data->ip_header->protocol);
		this->detail.InsertItem(str, ip);
		str.Format(_T("头部校验和：0x%04x"), local_data->ip_header->headerChecksum);
		this->detail.InsertItem(str, ip);

		str.Format(_T("发送方IP："));
		for (i = 0; i < 3; i++)
		{
			str.AppendFormat(_T("%d."), local_data->ip_header->sourceIpAddress[i]);
		}
		str.AppendFormat(_T("%d"), local_data->ip_header->sourceIpAddress[i]);
		this->detail.InsertItem(str, ip);

		str.Format(_T("接收方IP："));
		for (i = 0; i < 3; i++)
		{
			str.AppendFormat(_T("%d."), local_data->ip_header->destinationIpAddress[i]);
		}
		str.AppendFormat(_T("%d"), local_data->ip_header->destinationIpAddress[i]);
		this->detail.InsertItem(str, ip);

		
		if (local_data->ip_header->protocol ==1)							//ICMP
		{
			HTREEITEM icmp = this->detail.InsertItem(_T("ICMP协议头"), data);

			str.Format(_T("类型:%d"), local_data->icmp_header->type);
			this->detail.InsertItem(str, icmp);
			str.Format(_T("代码:%d"), local_data->icmp_header->code);
			this->detail.InsertItem(str, icmp);
			str.Format(_T("序列号:%d"), local_data->icmp_header->seq);
			this->detail.InsertItem(str, icmp);
			str.Format(_T("校验和:%d"), local_data->icmp_header->checksum);
			this->detail.InsertItem(str, icmp);

		}
		else if (local_data->ip_header->protocol==6) {				//TCP

			HTREEITEM tcp = this->detail.InsertItem(_T("TCP协议头"), data);

			str.Format(_T("  源端口:%d"), local_data->tcp_header->sourcePort);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), local_data->tcp_header->destPort);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%08x"), local_data->tcp_header->sequenceNumber);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  确认号:0x%08x"), local_data->tcp_header->ackNumber);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  头部长度:%d*4字节"), local_data->tcp_header->dataOffset);
			this->detail.InsertItem(str, tcp);
			HTREEITEM flag = this->detail.InsertItem(_T(" +标志位"), tcp);
			str.Format(_T("CWR %d"), local_data->tcp_header->cwr);
			this->detail.InsertItem(str, flag);
			str.Format(_T("ECE %d"), local_data->tcp_header->ece);
			this->detail.InsertItem(str, flag);
			str.Format(_T("URG %d"), local_data->tcp_header->urg);
			this->detail.InsertItem(str, flag);
			str.Format(_T("ACK %d"), local_data->tcp_header->ack);
			this->detail.InsertItem(str, flag);
			str.Format(_T("PSH %d"), local_data->tcp_header->psh);
			this->detail.InsertItem(str, flag);
			str.Format(_T("RST %d"), local_data->tcp_header->rst);
			this->detail.InsertItem(str, flag);
			str.Format(_T("SYN %d"), local_data->tcp_header->syn);
			this->detail.InsertItem(str, flag);
			str.Format(_T("FIN %d"), local_data->tcp_header->fin);
			this->detail.InsertItem(str, flag);

			str.Format(_T("  窗口大小:%d"), local_data->tcp_header->window);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  校验和:0x%04x"), local_data->tcp_header->checksum);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  紧急指针:%d"), local_data->tcp_header->urgentPointer);
			this->detail.InsertItem(str, tcp);
			
			//str.Format(_T("  选项:%d"), local_data->tcp_header->opt);
			//this->detail.InsertItem(str, tcp);
		}
		else if (local_data->ip_header->protocol==17) {				//UDP
			HTREEITEM udp = this->detail.InsertItem(_T("UDP协议头"), data);

			str.Format(_T("源端口:%d"), local_data->udp_header->sourcePort);
			this->detail.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), local_data->udp_header->destPort);
			this->detail.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), local_data->udp_header->length);
			this->detail.InsertItem(str, udp);
			str.Format(_T("校验和:0x%02x"), local_data->udp_header->checksum);
			this->detail.InsertItem(str, udp);
		}
		else {
			HTREEITEM other = this->detail.InsertItem(_T("IP上层非常见协议："), data);
			str.Format(_T("协议号：%d"), local_data->ip_header->protocol);
			this->detail.InsertItem(str, other);
		}
	}
	else if (local_data->ethernet_header->etherType==0x86dd ) {		//IPv6
		HTREEITEM ip6 = this->detail.InsertItem(_T("IPv6协议头"), data);

		
		str.Format(_T("版本:%d"), local_data->ipv6_header->version);
		this->detail.InsertItem(str, ip6);
		str.Format(_T("通信量类:%d"), local_data->ipv6_header->trafficClass);
		this->detail.InsertItem(str, ip6);
		
		str.Format(_T("流标号:%d"), local_data->ipv6_header->flowLabel);
		this->detail.InsertItem(str, ip6);
		str.Format(_T("有效载荷长度:%d"), local_data->ipv6_header->payloadLength);
		this->detail.InsertItem(str, ip6);
		str.Format(_T("下一个首部:0x%02x"), local_data->ipv6_header->nextHeader);
		this->detail.InsertItem(str, ip6);
		str.Format(_T("跳数限制:%d"), local_data->ipv6_header->hopLimit);
		this->detail.InsertItem(str, ip6);

		str.Format(_T("源地址:"));
		int n;
		for (n = 0; n < 7; n++)
		{
			
				str.AppendFormat(_T("%02x:"), local_data->ipv6_header->sourceAddress[n]);
			
				
		}
		str.AppendFormat(_T("%02x"), local_data->ipv6_header->sourceAddress[n]);
		this->detail.InsertItem(str, ip6);

		str.Format(_T("目的地址:"));
		for (n = 0; n < 7; n++)
		{
				str.AppendFormat(_T("%02x:"), local_data->ipv6_header->destinationAddress[n]);
		}
		str.AppendFormat(_T("%02x"), local_data->ipv6_header->destinationAddress[n]);
		this->detail.InsertItem(str, ip6);

		/*处理传输层ICMPv6、UDP、TCP*/
		if (local_data->ipv6_header->nextHeader==0x3a)							//ICMPv6
		{
			HTREEITEM icmp6 = this->detail.InsertItem(_T("ICMPv6协议头"), data);

			str.Format(_T("类型:%d"), local_data->icmpv6_header->type);
			this->detail.InsertItem(str, icmp6);
			str.Format(_T("代码:%d"), local_data->icmpv6_header->code);
			this->detail.InsertItem(str, icmp6);
			str.Format(_T("序号:%d"), local_data->icmpv6_header->seq);
			this->detail.InsertItem(str, icmp6);
			str.Format(_T("校验和:%d"), local_data->icmpv6_header->chksum);
			this->detail.InsertItem(str, icmp6);
			str.Format(_T("选项-类型:%d"), local_data->icmpv6_header->op_type);
			this->detail.InsertItem(str, icmp6);
			str.Format(_T("选项-长度%d"), local_data->icmpv6_header->op_len);
			this->detail.InsertItem(str, icmp6);
			str.Format(_T("选项-链路层地址:"));
			int i;
			for (i = 0; i < 5; i++)
			{
				str.AppendFormat(_T("%02x-"), local_data->icmpv6_header->op_ethaddr[i]);
			}

			str.AppendFormat(_T("%02x"), local_data->icmpv6_header->op_ethaddr[i]);
			this->detail.InsertItem(str, icmp6);

		}
		else if (local_data->ipv6_header->nextHeader==0x06) {				//TCP

			HTREEITEM tcp = this->detail.InsertItem(_T("TCP协议头"), data);

			str.Format(_T("  源端口:%d"), local_data->tcp_header->sourcePort);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), local_data->tcp_header->destPort);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%04x"), local_data->tcp_header->sequenceNumber);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  确认号:0x%04x"), local_data->tcp_header->ackNumber);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  头部长度:%d*4字节"), local_data->tcp_header->dataOffset);
			this->detail.InsertItem(str, tcp);
			HTREEITEM flag = this->detail.InsertItem(_T(" +标志位"), tcp);

			str.Format(_T("CWR %d"), local_data->tcp_header->cwr);
			this->detail.InsertItem(str, flag);
			str.Format(_T("ECE %d"), local_data->tcp_header->ece);
			this->detail.InsertItem(str, flag);
			str.Format(_T("URG %d"), local_data->tcp_header->urg);
			this->detail.InsertItem(str, flag);
			str.Format(_T("ACK %d"), local_data->tcp_header->ack);
			this->detail.InsertItem(str, flag);
			str.Format(_T("PSH %d"), local_data->tcp_header->psh);
			this->detail.InsertItem(str, flag);
			str.Format(_T("RST %d"), local_data->tcp_header->rst);
			this->detail.InsertItem(str, flag);
			str.Format(_T("SYN %d"), local_data->tcp_header->syn);
			this->detail.InsertItem(str, flag);
			str.Format(_T("FIN %d"), local_data->tcp_header->fin);
			this->detail.InsertItem(str, flag);

			str.Format(_T("  窗口大小:%d"), local_data->tcp_header->window);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  校验和:0x%04x"), local_data->tcp_header->checksum);
			this->detail.InsertItem(str, tcp);
			str.Format(_T("  紧急指针:%d"), local_data->tcp_header->urgentPointer);
			this->detail.InsertItem(str, tcp);
		/*	str.Format(_T("  选项:%d"), local_data->tcp_header->opt);
			this->detail.InsertItem(str, tcp);*/
		}
		else if (local_data->ipv6_header->nextHeader==0x11) {				//UDP
			HTREEITEM udp = this->detail.InsertItem(_T("UDP协议头"), data);

			str.Format(_T("源端口:%d"), local_data->udp_header->sourcePort);
			this->detail.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), local_data->udp_header->destPort);
			this->detail.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), local_data->udp_header->length);
			this->detail.InsertItem(str, udp);
			str.Format(_T("校验和:0x%02x"), local_data->udp_header->checksum);
			this->detail.InsertItem(str, udp);
		}
	}
	// 找到树的根节点
	HTREEITEM rootItem = this->detail.GetRootItem();

	// 调用递归展开函数
	ExpandAllItems(this->detail, rootItem);
	return 1;
}

int  CsnifferDlg::sniff_content(int index)
{
	POSITION local_pos, network_pos;
	local_pos = this->localData.FindIndex(index);
	network_pos = this->networkData.FindIndex(index);

	struct data_save* local_data = (struct data_save*)(this->localData.GetAt(local_pos));
	u_char* net_data = (u_char*)(this->networkData.GetAt(network_pos));

	CString buf;
	print_packet_hex(net_data, local_data->len, buf);
	//this-
	this->content.SetWindowText(buf);

	return 1;
}
int CsnifferDlg::sniff_save()
{
	CFileFind find;
	if (NULL == find.FindFile(CString(filepath)))
	{
		MessageBox(_T("保存文件遇到未知意外"));
		return -1;
	}

	//打开文件对话框
	CFileDialog   FileDlg(FALSE, _T("pcap"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT);
	FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");
	if (FileDlg.DoModal() == IDOK)  
	{
		CopyFile(CString(filepath), FileDlg.GetPathName(), TRUE);
	}
	return 1;
}
int CsnifferDlg::sniff_read(CString path)
{
		number = 1;
		int res, nItem, i;
		struct tm* ltime;
		CString timestr, buf, srcMac, destMac;
		time_t local_tv_sec;
		struct pcap_pkthdr* header;									  
		const u_char* pkt_data = NULL;     
		u_char* ppkt_data;

		CsnifferDlg* pthis = this;						
		pcap_t* fp;
	
		int len = path.GetLength() + 1;							
		char* charpath = (char*)malloc(len);
		memset(charpath, 0, len);
		if (NULL == charpath)
			return -1;

		for (i = 0; i < len; i++)
			charpath[i] = (char)path.GetAt(i);

		//打开相关文件
		if ((fp = pcap_open_offline( /*(char*)(LPCTSTR)path*/charpath, errbuf)) == NULL)
		{
			MessageBox(_T("打开文件错误") + CString(errbuf));
			return -1;
		}

		while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
		{
			struct data_save* data = (struct data_save*)malloc(sizeof(struct data_save));
			memset(data, 0, sizeof(struct data_save));

			if (!data)
			{
				MessageBox(_T("空间已满，无法接收新的数据包"));
				return  -1;
			}

			if (analyze_frame(pkt_data, data) < 0)
				continue;
				
			ppkt_data = (u_char*)malloc(header->len);
			memcpy(ppkt_data, pkt_data, header->len);

			pthis->localData.AddTail(data);
			pthis->networkData.AddTail(ppkt_data);

			/*预处理，获得时间、长度*/
			data->len = header->len;								//链路中收到的数据长度
			local_tv_sec = header->ts.tv_sec;
			ltime = localtime(&local_tv_sec);
			data->time[0] = ltime->tm_year + 1900;
			data->time[1] = ltime->tm_mon + 1;
			data->time[2] = ltime->tm_mday;
			data->time[3] = ltime->tm_hour;
			data->time[4] = ltime->tm_min;
			data->time[5] = ltime->tm_sec;

			/*为新接收到的数据包在listControl中新建一个item*/
			buf.Format(_T("%d"), pthis->number);
			nItem = pthis->data_packets.InsertItem(pthis->number, buf);

			/*显示时间戳*/
			timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
				data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
			pthis->data_packets.SetItemText(nItem, 1, timestr);

			/*显示长度*/
			buf.Empty();
			buf.Format(_T("%d"), data->len);
			pthis->data_packets.SetItemText(nItem, 2, buf);

			/*显示源MAC*/
			buf.Empty();
			buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethernet_header->srcMac[0], data->ethernet_header->srcMac[1],
				data->ethernet_header->srcMac[2], data->ethernet_header->srcMac[3], data->ethernet_header->srcMac[4], data->ethernet_header->srcMac[5]);
			pthis->data_packets.SetItemText(nItem, 3, buf);

			/*显示目的MAC*/
			buf.Empty();
			buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethernet_header->destMac[0], data->ethernet_header->destMac[1],
				data->ethernet_header->destMac[2], data->ethernet_header->destMac[3], data->ethernet_header->destMac[4], data->ethernet_header->destMac[5]);
			pthis->data_packets.SetItemText(nItem, 4, buf);

			/*获得协议*/
			pthis->data_packets.SetItemText(nItem, 5, CString(data->save_type));

			/*获得源IP*/
			buf.Empty();
			if (0x0806 == data->ethernet_header->etherType)
			{
				buf.Format(_T("%d.%d.%d.%d"), data->arp_header->senderProtocolAddr[0],
					data->arp_header->senderProtocolAddr[1],
					data->arp_header->senderProtocolAddr[2],
					data->arp_header->senderProtocolAddr[3]);
			}
			else if (0x0800 == data->ethernet_header->etherType) {
				buf.Format(_T("%d.%d.%d.%d"), data->ip_header->sourceIpAddress[0],
					data->ip_header->sourceIpAddress[1],
					data->ip_header->sourceIpAddress[2],
					data->ip_header->sourceIpAddress[3]
				);
			}
			else if (0x86dd == data->ethernet_header->etherType) {
				int n;
				for (n = 0; n < 7; n++)
				{
					buf.AppendFormat(_T("%02x:"), data->ipv6_header->sourceAddress[n]);
				}
				buf.AppendFormat(_T("%02x"), data->ipv6_header->sourceAddress[7]);
			}
			pthis->data_packets.SetItemText(nItem, 6, buf);

			/*获得目的IP*/
			buf.Empty();
			if (0x0806 == data->ethernet_header->etherType)
			{
				buf.Format(_T("%d.%d.%d.%d"), data->arp_header->targetProtocolAddr[0],
					data->arp_header->targetProtocolAddr[1],
					data->arp_header->targetProtocolAddr[2],
					data->arp_header->targetProtocolAddr[3]);
			}
			else if (0x0800 == data->ethernet_header->etherType) {
				buf.Format(_T("%d.%d.%d.%d"), data->ip_header->destinationIpAddress[0],
					data->ip_header->destinationIpAddress[1],
					data->ip_header->destinationIpAddress[2],
					data->ip_header->destinationIpAddress[3]);
			}
			else if (0x86dd == data->ethernet_header->etherType) {
				int n;
				for (n = 0; n < 8; n++)
				{
					buf.AppendFormat(_T("%02x:"), data->ipv6_header->destinationAddress[n]);
				}
				buf.AppendFormat(_T("%02x"), data->ipv6_header->destinationAddress[7]);
			}

			pthis->data_packets.SetItemText(nItem, 7, buf);
			pthis->number++;
		}

		pcap_close(fp);

		return 1;
	
}

void CsnifferDlg::OnEnChangeEdit2()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}
