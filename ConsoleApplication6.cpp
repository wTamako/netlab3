#include <Winsock2.h>
#include<Windows.h>
#include<iostream>
#include <ws2tcpip.h>
#include <pcap.h>
#include "stdio.h"
#include<time.h>
#include <string>
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning( disable : 4996 )
#define _WINSOCK_DEPRECATED_NO_WARNINGS

using namespace std;
#pragma pack(1)
// 定义以太网帧头部结构体
typedef struct FrameHeader_t {
	BYTE DesMAC[6];        // 目标 MAC 地址
	BYTE SrcMAC[6];        // 源 MAC 地址
	WORD FrameType;        // 帧类型
} FrameHeader_t;

// 定义 ARP 数据包结构体
typedef struct ARPFrame_t {
	FrameHeader_t FrameHeader;  // 以太网帧头部
	WORD HardwareType;         // 硬件类型
	WORD ProtocolType;         // 协议类型
	BYTE HLen;                 // 硬件地址长度
	BYTE PLen;                 // 协议地址长度
	WORD Operation;            // 操作类型
	BYTE SendHa[6];            // 发送方硬件地址（MAC 地址）
	DWORD SendIP;              // 发送方 IP 地址
	BYTE RecvHa[6];            // 接收方硬件地址（MAC 地址）
	DWORD RecvIP;              // 接收方 IP 地址
} ARPFrame_t;
#pragma pack()   
int main()
{
	// 定义用于存储错误信息的缓冲区
	char errbuf[PCAP_ERRBUF_SIZE];
	// 定义指向所有网络接口信息的指针
	pcap_if_t* alldevs;
	// 定义指向当前网络接口的指针
	pcap_if_t* ptr;
	// 定义指向网络接口地址的指针
	pcap_addr_t* a;
	// 用于迭代网络接口的计数器
	int i = 0;
	// 用于存储解析后的 ARP 数据包的指针
	ARPFrame_t* IPPacket;
	// 定义用于存储捕获到的数据包的头部信息的指针
	struct pcap_pkthdr* pkt_header;
	// 定义用于存储捕获到的数据包的内容的指针
	const u_char* pkt_data;

	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		return 1;
	}
	// 显示接口列表 遍历所有网络接口并输出相关信息
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		cout << "网卡" << i + 1 << "\t" << ptr->name << endl;
		cout << ptr->description << endl;
		// 遍历该网卡的地址信息
		for (a = ptr->addresses; a != NULL; a = a->next)
		{
			// 判断地址类型是否为 IPv4
			if (a->addr->sa_family == AF_INET)
			{
				// 输出该网卡的 IPv4 地址
				cout << "  IP地址：" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
			}
		}
		i++;  
	}

	int num;
	cout << "请选要打开的网卡号：";
	cin >> num;
	ptr = alldevs;
	for (int i = 1; i < num; i++)
	{
		ptr = ptr->next;
	}

	pcap_t* handle = pcap_open(ptr->name,          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	);
	if (handle == NULL) {
		cout << "Error opening device: " << errbuf << endl;
		return 1;
	}

	//输入目标ip地址
	char* desip = new char[20];
	cout << "输入目标ip地址" << endl;
	cin >> desip;

	//报文内容
	ARPFrame_t ARPFrame;
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;
		ARPFrame.RecvHa[i] = 0xFF;
		ARPFrame.SendHa[i] = 0x66;
	}
	// 设置以太网帧类型为 ARP
	ARPFrame.FrameHeader.FrameType = htons(0x806);
	// 设置硬件类型为 Ethernet（0x0001）
	ARPFrame.HardwareType = htons(0x0001);
	// 设置协议类型为 IPv4（0x0800）
	ARPFrame.ProtocolType = htons(0x0800);
	// 设置硬件地址长度为 6 字节（MAC 地址长度）
	ARPFrame.HLen = 6;
	// 设置协议地址长度为 4 字节（IPv4 地址长度）
	ARPFrame.PLen = 4;
	// 设置 ARP 操作类型为请求（0x0001）
	ARPFrame.Operation = htons(0x0001);
	// 设置发送方 IP 地址为固定值 122.122.122.122
	ARPFrame.SendIP = inet_addr("122.122.122.122");
	// 设置接收方 IP 地址为用户输入的目标 IP 地址
	ARPFrame.RecvIP = inet_addr(desip);
	
	// 使用pcap_sendpacket发送构造好的ARP数据包
	pcap_sendpacket(handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));

	// 循环监听网络接口，等待捕获到符合条件的数据包
	while (true)
	{
		// 调用pcap_next_ex捕获下一个数据包的头部信息和内容
		int rtn = pcap_next_ex(handle, &pkt_header, &pkt_data);
		// 如果捕获到数据包
		if (rtn == 1)
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			// 判断捕获到的数据包是否是目标的 ARP 响应
			if (IPPacket->RecvIP == ARPFrame.SendIP && IPPacket->SendIP == ARPFrame.RecvIP)
			{
				cout << "IP地址与MAC地址的对应关系：" << endl;
				BYTE* p = (BYTE*)&IPPacket->SendIP;
				for (int i = 0; i < 4; i++)
				{
					cout << dec << (int)*p << ".";//四个8位字节，以十进制格式输出
					p++;
				}
				cout << endl;
				for (int i = 0; i < 6; i++)
				{
					if (i < 5)
						printf("%02x-", IPPacket->SendHa[i]);//两位十六进制输出，不足两位前面用零填充
					else
						printf("%02x", IPPacket->SendHa[i]);
				}
				cout << endl;
				// 跳出循环，结束程序
				break;
			}
		}
	}
	delete[] desip;
	// 释放设备列表
	pcap_freealldevs(alldevs);
	return 0;
}