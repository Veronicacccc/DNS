#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h> 
#include <windows.h> 
#include <time.h> 
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <Windows.h>
#include <process.h>

#include "file.h"


#pragma  comment(lib, "Ws2_32.lib") 

#define BUFSIZE 1024	//报文最大字节
#define PORT_NO 53		//端口名（本地及外部）
#define AMOUNT 16		//ID转换表大小
#define TTL 10			//生存期（ID、记录）

using namespace std;


int debug_level = 0;
char* fileName;

//设置ID转换表
typedef struct Change
{
	unsigned short OID;//原ID
	int State;//是否完成功能（1完成0未完成）
	SOCKADDR_IN Address;//原套接字
	int Etime;			//ID过期时间
}IDChange;
IDChange IDTranstable[AMOUNT];	//设置ID转换表，大小为AMOUNT
int IDcount = 0;				//ID转换表中使用中的ID个数

//SOCKET通信
WSADATA wsaData;//打开网络库
SOCKET local_socket, outside_socket;			//创建套接字（本地套接字与外部套接字）
struct sockaddr_in local_name, outside_name;	//外部服务器 和 本地客户端地址
struct sockaddr_in client;						//本地客户端地址（无需展示详细）
char DNS_ADDRESS[16] = "114.114.114.114";		//外部服务器初始IP地址
int len1, len2;

//DNS相关
typedef unsigned short U16;//2字节（16位)

typedef struct _DNS_HDR//DNS头部
{
	U16 id;//事务ID
	U16 flag;//标志（其中包含响应码Rcode）
	U16 qnum;//问题计数
	U16 anum;//回答问题计数
	U16 num1;//权威名称服务器计数
	U16 num2;//附加资源记录数
}DNS_HDR;

typedef struct _DNS_QER//问题部分除域名外
{
	U16 type;//查询类型（一般用A)——00 01
	U16 classes;//查询类(一般为IN)——00 01
}DNS_QER;

//设置过期时间（当前时间+TTL）
void set_etime(IDChange* p)
{
	time_t now_time;
	now_time = time(NULL);
	p->Etime = now_time + TTL;
}

//判断是否过期（过期返回1、未过期返回0）
int is_time_out(IDChange* p)
{
	time_t now_time;
	now_time = (NULL);
	if (p->Etime > 0 && p->Etime <= now_time)
		return 1;
	return 0;
}
/*
并行解决措施：
改变原ID，为其分配新ID
*/

//ID转换过程，返回转换后的新ID
unsigned short Trans(unsigned short oldID, SOCKADDR_IN address)
{
	for (int i = 0; i < AMOUNT; i++)
	{
		if (is_time_out(&IDTranstable[i]) == 1 || IDTranstable[i].State == 1)//已完成或已过期
		{
			IDTranstable[i].OID = oldID;		//原ID
			IDTranstable[i].Address = address;	//客户端的地址
			IDTranstable[i].State = 0;			//设置为未完成功能
			set_etime(&IDTranstable[i]);		//设置过期时间
			IDcount++;
		}
		if (i == AMOUNT)
			return 0;							//没有找到可写的位置
		return (unsigned short)(i + 1);			//以在转换表中位置（第几个，从1开始算）作为新的ID
	}
}

//读取域名将其格式化——将3www5baidu3com转为www.baidu.com
void readurl(char* buf, char* dest)
{
	int len = strlen(buf);
	int i = 0, j = 0, k = 0;
	while (i < len)
	{
		if (buf[i] > 0 && buf[i] <= 63)
		{
			for (j = buf[i], i++; j > 0; j--, i++, k++)
				dest[k] = buf[i];
		}
		if (buf[i] != 0)
		{
			dest[k] = '.';
			k++;
		}
	}
	dest[k] = '\0';
}

/*收到远端的报文
1.首先取flag中的Rcode判断是否有异常
2.将ID改成原ID，顺便找到原客户端的地址
3.找到url
4.找到A类型的IP地址
5.将域名和IP地址存入文件——只存了一个IP地址
6.把它转发到本地客户端
*/

//从远端DNS接收报文并转发到本机
void receive_from_out()
{
	char buf[BUFSIZE], url[65];
	int length = -1;
	ip_addr ip;				//ip_addr是string类型
	int ip1, ip2, ip3, ip4;	//ip才用点分十进制法，16字节分四部分
	int nquery, nresponse;	//问题个数、回答个数
	unsigned char rcode;	//响应码——异常情况处理
	unsigned short query_result1, query_result2;
	length = recvfrom(outside_socket, buf, sizeof(buf), 0, (struct sockaddr*)&outside_name, &len1);//接受外部DNS报文消息，此时自己作为客户端
	//若接收到数据包
	if (length > -1)
	{
		if (debug_level == 2)
			printf("成功接收远端服务器发送的数据包\n");
		//异常情况处理
		//先取标志位flag，再取flag中的Rcode
		memcpy(&query_result1, &buf[2], sizeof(unsigned short));
		query_result2 = ntohs(query_result1);		//网络转主机字节序
		rcode = query_result2 % 16;					//取flag（16位）中的最低4位
		if (rcode == 0x01)
		{	//响应码为1
			printf("报文格式错误\n");
			return;
		}
		if (rcode == 0x02)
		{	//响应码为2
			printf("域名服务器失败\n");
			return;
		}
		if (rcode == 0x03)
		{	//响应码为3
			printf("解析的域名不存在\n");
			return;
		}
		if (rcode == 0x04)
		{	//响应码为4
			printf("查询类型不支持\n");
			return;
		}
		if (rcode == 0x05)
		{	//响应码为5
			printf("服务器拒绝给出应答\n");
			return;
		}

		//求取原ID，将接收到的数据包的ID部分换为原ID
		unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short));
		memcpy(pID, buf, sizeof(unsigned short));
		(*pID) = ntohs(*pID);
		int id_index = (*pID) - 1;//即原ID所储存的地址
		free(pID);

		//id_index指向在转换表中找到的表项
		unsigned short oID = IDTranstable[id_index].OID;
		memcpy(buf, &oID, sizeof(unsigned short));	//此时这个数据包已经可以发回去了

		IDcount--;									//使用中的ID个数减1
		//printf("%d id in id buffer\n", IDcount);

		IDTranstable[id_index].State = 1;			//功能已完成，状态设置为1
		client = IDTranstable[id_index].Address;	//从表中找到此条DNS请求的客户端发送者

		//ntohs从网络字节序转化为主机字节序
		nquery = ntohs(*((unsigned short*)(buf + 4)));	//问题个数（2字节）
		nresponse = ntohs(*((unsigned short*)(buf + 6)));//回答个数 （2字节） 

		char* p = buf + 12; //指针跳过DNS头部（头部为12字节）

		//只记录最后一个问题的url
		for (int i = 0; i < nquery; i++)
		{
			readurl(p, url);
			while (*p > 0)			//跳过上述的那个url
				p += (*p) + 1;
			p += 5;					//跳过url后的查询类型和查询类，指向下一个问题的url
		}
		if (nresponse > 0 && debug_level >= 1)
		{
			time_t timep;
			struct tm* p;
			time(&timep);
			p = gmtime(&timep);
			printf("%d.%d.%d %t %02d:%02d:%02d %t————", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, 8 + p->tm_hour, p->tm_min, p->tm_sec);
			printf("receive outside %s\n", url);
		}

		//分析回复，此时指针已经指到了Answer区最上
		for (int i = 0; i < nresponse; i++)
		{
			if ((unsigned char)*p == 0xc0) //是指针就跳过，一字节8位
				p += 2;
			else
			{
				while (*p > 0)//是url的话，根据计数跳过url
					p += (*p) + 1;
				++p;    //指向后面的内容
			}
			//ntohs\ntohl从网络字节序转化为主机字节序
			unsigned short resp_type = ntohs(*(unsigned short*)p);  //回复类型A 00 01
			p += 2;

			unsigned short resp_class = ntohs(*(unsigned short*)p); //回复类IN 00 01
			p += 2;

			unsigned long ttl = ntohl(*(unsigned long*)p);			//生存时间ttl 00 00 00 33
			p += 4;

			int datalen = ntohs(*(unsigned short*)p);				//后面数据长度
			p += 2;


			if (resp_type == 1)	//是A类型，回复的是url的ip
			{
				memset(ip.addr, 0, 16);
				//读取4个ip部分
				ip1 = (unsigned char)*p++;
				ip2 = (unsigned char)*p++;
				ip3 = (unsigned char)*p++;
				ip4 = (unsigned char)*p++;

				//存入一串字符
				sprintf(ip.addr, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
				if (debug_level == 2)
					printf("ip %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);

				// 缓存从外部服务器中接受到的域名对应的IP
				add_record(url, ip.addr, TTL);
				//只保存第一条回答
				break;
			}
			else p += datalen;  //直接跳过
		}
		length = sendto(local_socket, buf, length, 0, (SOCKADDR*)&client, sizeof(client));//把buf转发至请求者处，此时自己作为服务器端
		if (debug_level == 2)
			printf("成功向本地客户端发送域名%s 的IP\n", url);
	}
}
/*接收到本地客户端发来的报文
1.获取域名
2.判断类型是否为A
3.在文件中查找域名对应ip
4.若没有找到或已过期，转换ID将其发送给外部
若找到ip，首先改变flag（由0x0100变为0x8180)
再判断是否被屏蔽，被屏蔽回答数设为0，否则设为1
增加回答部分（16字节）再发送给客户端
包括域名指针（2字节）类型（2字节）类（2字节）ttl（4字节）长度（2字节）IP（4字节）
*/
//从本机读取DNS查询，从缓存读取或发送到外部DNS服务器查询
void receive_from_local()
{
	char buf[BUFSIZE], url[65];
	memset(buf, 0, BUFSIZE);
	int length = -1;
	//接收本地客户端的请求报文
	length = recvfrom(local_socket, buf, sizeof(buf), 0, (struct sockaddr*)&client, &len2);
	if (length > 0)
	{
		if (debug_level == 2)
			printf("成功接收本地客户端发送的数据包\n");

		DNS_QER question;
		char ori_url[200];
		memcpy(ori_url, &(buf[sizeof(DNS_HDR)]), length);	//获取请求报文中的域名表示
		readurl(ori_url, url);
		if (debug_level == 2)
			printf("本地域名 %s\n", url);
		if (debug_level >= 1)
		{
			time_t timep;
			struct tm* p;
			time(&timep);
			p = gmtime(&timep);
			printf("%d.%d.%d %t %02d:%02d:%02d %t————", 1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, 8 + p->tm_hour, p->tm_min, p->tm_sec);
			printf("receive local %s\n", url);
		}
		char buff_2[2];
		//获取请求报文中的类型
		int offset = sizeof(DNS_HDR) + strlen(url) + 2;
		for (int j = 0; j < 2; j++) {
			buff_2[j] = buf[j + offset];
		}
		question.type = (buff_2[0] << 8) + buff_2[1];
		offset += 2;

		//获取报文类
		for (int j = 0; j < 2; j++)
		{
			buff_2[j] = buf[j + offset];
		}
		question.classes = (buff_2[0] << 8) + buff_2[1];


		if (question.type != 1)
		{
			if (debug_level == 2)
				printf("报文类型非A类型，不处理！\n");
			return;
		}
		ip_addr ip = get_ip(url);		//从缓存中查找该域名对应的IP
		if (ip.addr[0] == 'n' || ip.addr[0] == 'e')		//在缓存中未找到对应的IP或者该域名对应的IP已经过期
		{
			if (debug_level == 2)
			{
				if (ip.addr[0] == 'n')
				{
					printf("在本机DNS服务器中未查找到客户端请求的域名\n");
				}
				else if (ip.addr[0] == 'e')
				{
					printf("在本机DNS服务器中查找到客户端请求的域名已失效（已超时）\n");
				}
			}
			//求取新ID，将接收到的数据包的ID部分换为新的ID，新ID即转换表中的位置
			unsigned short* pID = (unsigned short*)malloc(sizeof(unsigned short));
			memcpy(pID, buf, sizeof(unsigned short));		//记录ID
			unsigned short nID = Trans(*pID, client);   //储存ID和该发送方的地址client


			if (nID == 0)
			{
				if (debug_level == 2)
					puts("本机DNS服务器的转换表内存已满\n");
			}
			else
			{
				if (debug_level == 2)
					printf("转换表中的新的ID号为：%d\n", nID);
				//将该数据包转发给远端DNS
				nID = htons(nID);
				memcpy(buf, &nID, sizeof(unsigned short));
				length = sendto(outside_socket, buf, length, 0, (struct sockaddr*)&outside_name, sizeof(outside_name));  //将该请求发送给外部服务器
				if (debug_level == 2)
					printf("成功将域名为 %s 的数据包转发给远端服务器\n", url);
			}
			free(pID);
		}
		else
		{
			if (debug_level == 2)
				printf("成功在本机DNS服务器中查找到客户端请求的域名（未超时）\n");
			char sendbuf[BUFSIZE];
			memcpy(sendbuf, buf, length);		//拷贝请求报文

			if (strcmp(ip.addr, "0.0.0.0") == 0) //判断是否需要屏蔽该域名的回答
			{
				unsigned short a = htons(0x8183);
				memcpy(&sendbuf[2], &a, sizeof(unsigned short));	//修改标志域

				a = htons(0x0000);	//屏蔽功能：将回答数置为0
				if (debug_level == 2)
					printf("查找到该域名IP为：0.0.0.0\n");

				memcpy(&sendbuf[6], &a, sizeof(unsigned short));
			}
			else
			{

				unsigned short a = htons(0x8180);
				memcpy(&sendbuf[2], &a, sizeof(unsigned short));	//修改标志域
				a = htons(0x0001);	//服务器功能：将回答数置为1

				memcpy(&sendbuf[6], &a, sizeof(unsigned short));
			}

			int curLen = 0;
			char answer[16];
			unsigned short Name = htons(0xc00c);//域名指针（偏移量）
			memcpy(answer, &Name, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned short TypeA = htons(0x0001);  //类型 A 00 01
			memcpy(answer + curLen, &TypeA, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned short ClassA = htons(0x0001);  //查询类IN 互联网类 00 01
			memcpy(answer + curLen, &ClassA, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned long timeLive = htonl(0x33);  //生存时间ttl 00 00 00 33
			memcpy(answer + curLen, &timeLive, sizeof(unsigned long));
			curLen += sizeof(unsigned long);

			unsigned short IPLen = htons(0x0004);  //资源数据长度
			memcpy(answer + curLen, &IPLen, sizeof(unsigned short));
			curLen += sizeof(unsigned short);

			unsigned long IP = (unsigned long)inet_addr(ip.addr);  //资源数据即IP
			memcpy(answer + curLen, &IP, sizeof(unsigned long));
			curLen += sizeof(unsigned long);
			curLen += length;
			memcpy(sendbuf + length, answer, sizeof(answer));
			//发送该数据包
			length = sendto(local_socket, sendbuf, curLen, 0, (SOCKADDR*)&client, sizeof(client));

			char* p;
			p = sendbuf + length - 4;
			if (debug_level == 2)
				printf("向本地客户端发送 %s -> %u.%u.%u.%u\n", url, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
		}
	}
}

void parseArgu(int argc, char** argv)
{
	fileName = (char*)malloc(sizeof(char) * strlen("dnsrelay.txt"));
	strcpy(fileName, "dnsrelay.txt");
	int offset = 1;
	while (offset < argc) {
		if (!strcmp(argv[offset], "-d"))
		{
			debug_level = 1;
			printf("打印第一等级的调试信息 \n");
			offset++;
		}
		else if (!strcmp(argv[offset], "-dd"))
		{
			debug_level = 2;
			printf("打印第二等级的调试信息\n");
			offset++;
		}
		else if (argv[offset][0] != '-')
		{
			fileName = (char*)malloc(sizeof(char) * strlen(argv[offset]));
			strcpy(fileName, argv[offset]);
			printf("读入文件 : %s\n", fileName);
			offset++;
		}
		else
		{
			printf("无效文件 ! ::: %s\n", argv[offset]);
			exit(1);
		}
	}
}
/*主函数功能：
1.初始化转换表
2.进行UDP通信——（1）打开网络库（2）创建套接字（本地与外部）（3）设置接口为非阻塞模式、设置超时机制 （4）绑定本地套接字
3.文件初始化
4.开始循环接收
5.结束后清除套接字、关闭网络库
注：阻塞模式没有收到消息就一直等待，非阻塞模式可连续接收消息
*/
int main(int argc, char** argv)
{
	parseArgu(argc, argv);
	printf("Debug level: %d\n", debug_level);

	//初始化ID转换表
	for (int i = 0; i < AMOUNT; i++)
	{
		IDTranstable[i].OID = 0;
		IDTranstable[i].State = 1;//初始化为1，表示可占用
		IDTranstable[i].Etime = 0;
		memset(&(IDTranstable[i].Address), 0, sizeof(SOCKADDR_IN));
	}
	//进行socket通信
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		if (debug_level >= 1)
			printf("打开网络库失败！");
		system("pause");
		return 0;
	}
	local_socket = socket(AF_INET, SOCK_DGRAM, 0);
	outside_socket = socket(AF_INET, SOCK_DGRAM, 0);

	if (debug_level == 2)
		printf("创建套接字成功！\n");


	//设置接口为非阻塞
	int unblock = 1;
	ioctlsocket(local_socket, FIONBIO, (u_long FAR*) & unblock);
	ioctlsocket(outside_socket, FIONBIO, (u_long FAR*) & unblock);

	local_name.sin_family = AF_INET;
	local_name.sin_port = htons(PORT_NO);//从主机字节序转移为网络字节序
	local_name.sin_addr.S_un.S_addr = inet_addr("0.0.0.0");//——广播网络

	outside_name.sin_family = AF_INET;
	outside_name.sin_port = htons(PORT_NO);
	outside_name.sin_addr.S_un.S_addr = inet_addr(DNS_ADDRESS);
	if (debug_level >= 1)
		printf("远端服务器IP：%s\n", DNS_ADDRESS);


	//设定超时机制
	int reuse = 1;
	setsockopt(local_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

	bind(local_socket, (struct sockaddr*)&local_name, sizeof(local_name));
	len1 = sizeof(outside_name);
	len2 = sizeof(client);
	if (debug_level == 2)
		printf("成功绑定本机服务器的套接字！\n");
	init_transtable();
	if (debug_level >= 1)
		printf("成功载入本地文件“%s”作为域名与IP的转换表\n", fileName);
	if (debug_level == 2)
		printf("所有条件已准备就绪，开始进行通信！\n");
	while (1)
	{
		receive_from_local();
		receive_from_out();
	}

	//清除套接字，关闭网络库
	closesocket(local_socket);
	closesocket(outside_socket);
	WSACleanup();

	system("pause");
	return 0;
}
