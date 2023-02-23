#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <iomanip>

#include "file.h"

using namespace std;
extern char* fileName;
extern int debug_level;
//创建基类
class UrlAndIp
{
public:
	int status;		//状态（有效为1，无效（超时、不存在）为0）
	int time;		//过期时间 
	string url;		//域名
	string ip;		//IP地址 
};
//创建向量存储所有记录的域名IP相关信息
vector <UrlAndIp> tables;


//将向量表中的信息存入缓存文件dns.txt中 
void out_file(void)
{
	ofstream fileout("dns.txt");
	if (!fileout.is_open())
	{
		cout << "文件打开错误！" << endl;
	}
	//将记录的总条数写入文件中
	fileout << tables.size() << endl;
	//依次向文件中写入每条记录
	for (int i = 0; i < tables.size(); i++)
	{
		fileout << tables.at(i).status << endl;
		fileout << tables.at(i).time << endl;
		fileout << tables.at(i).url << endl;
		fileout << tables.at(i).ip << endl;
	}
	//关闭文件
	fileout.close();
	return;
}

//设置过期时间
void set_expire(int* expire_time, int ttl)
{
	time_t now_time;
	now_time = time(NULL);
	*expire_time = now_time + ttl;//过期时间=当前时间+生存期
}

//初始化，将原文件中信息存入向量
void init_transtable(void)
{
	UrlAndIp urlAndip;

	//打开预先存在的文件dnsrelay.txt
	ifstream filein(fileName);
	if (!filein.is_open())
	{
		cout << "文件打开错误" << endl;
	}
	while (!filein.eof())
	{
		urlAndip.status = 1;	//该条记录有效 
		urlAndip.time = 0;		//过期时间为无限制 
		filein >> urlAndip.ip;	//获取ip字符串 
		filein >> urlAndip.url;	//获取url字符串 
		tables.push_back(urlAndip);	//存入向量 
	}
	filein.close();
	//将向量表中的内容输出到文件中
	out_file();
	return;
}

//检查某条记录是否超时
int is_expired(int expire_time)
{
	//0代表时间无限制
	if (expire_time == 0)
	{	//返回0表示未超时
		return 0;
	}
	else
	{
		time_t now_time;
		now_time = time(NULL);
		if (now_time > expire_time)
		{
			return 1;//超时返回1
		}

		return 0;//未超时返回0
	}
}

//新加入一个记录
void add_record(char* url, char* addr1, int ttl)
{
	int num_record = tables.size();
	UrlAndIp urlAndip;
	string addr = addr1;

	//这个记录将要写入的位置
	int url_pos = -1, expired_pos = -1, empty_pos = -1;
	for (int i = 0; i < num_record; i++)
	{
		int expire_time = tables.at(i).time;
		if (tables.at(i).url == url)
		{
			//在向量表中找到了这个url
			url_pos = i;
			//直接break,准备更新这个记录
			break;
		}
		else if (tables.at(i).status == 0 && empty_pos == -1)
		{	//在向量表中找到了无效记录
			empty_pos = i;
		}
		else
		{
			if (is_expired(expire_time) == 1)	//是否超时
			{
				//如果是超时记录，记下这个位置，准备替换这个记录
				expired_pos = i;
				break;
			}
		}
	}

	if (url_pos < 0)//表示在向量表中没有找到相同的url
	{
		if (expired_pos >= 0)	//找到了已超时的位置
		{
			//用新的记录替换超时记录的内容
			tables.at(expired_pos).status = 1;	//该条记录有效 
			tables.at(expired_pos).url = url;	//设置url字符串
			tables.at(expired_pos).ip = addr;	//设置ip字符串
			set_expire(&tables.at(expired_pos).time, ttl);	//设置过期时间
		}
		else if (empty_pos >= 0)	//找到了无效记录
		{
			//用新的记录替换无效记录的内容
			tables.at(empty_pos).status = 1;	//该条记录有效 
			tables.at(empty_pos).url = url;		//设置url字符串
			tables.at(empty_pos).ip = addr;		//设置ip字符串
			set_expire(&tables.at(empty_pos).time, ttl);//设置过期时间
		}
		else
		{	//在向量表中未找到url且没有超时或无效的记录
			//则在tables末尾新插入一条记录
			UrlAndIp urlAndip;		//新定义对应表
			urlAndip.status = 1;	//该条记录有效 
			urlAndip.ip = addr;		//设置ip字符串 
			urlAndip.url = url;		//设置url字符串 
			set_expire(&urlAndip.time, ttl);//设置过期时间
			tables.push_back(urlAndip);	//存入向量 
		}
	}
	else
	{	//找到了相同的url,更换该条记录
		tables.at(url_pos).status = 1;	//该条记录有效 
		tables.at(url_pos).url = url;	//设置url字符串
		tables.at(url_pos).ip = addr;	//设置ip字符串
		set_expire(&tables.at(url_pos).time, ttl);//设置过期时间
	}
	out_file();
}

//根据域名查询IP地址
ip_addr get_ip(char* query_url)
{
	ip_addr result;
	result.addr[0] = { 0 };//初始化，存储结果
	int num_record;
	UrlAndIp urlAndip;
	num_record = tables.size();
	//线性查找url的位置
	int url_index = -1;
	for (int i = 0; i < num_record; i++)
	{
		//在向量表中查找这个url
		if (tables.at(i).url == query_url)
		{
			url_index = i;
			if (debug_level == 2)
			{
				printf("此条信息在文件中位于第%d行\n", (url_index + 1));
			}
			if (is_expired(tables.at(i).time) == 1)//已过期
			{
				tables.at(i).status = 0;//状态设为无效
				if (debug_level == 2)
				{
					printf("该记录已过期！！！\n");
				}
				result.addr[0] = 'e';
				out_file();
				return result;
			}
			break;
		}
	}
	if (url_index == -1)//没有找到这个url,返回查找结果——未找到
	{
		result.addr[0] = 'n';
	}
	else
	{
		strcpy(result.addr, tables.at(url_index).ip.c_str());
	}
	out_file();
	return result;
}