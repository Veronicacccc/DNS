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
//��������
class UrlAndIp
{
public:
	int status;		//״̬����ЧΪ1����Ч����ʱ�������ڣ�Ϊ0��
	int time;		//����ʱ�� 
	string url;		//����
	string ip;		//IP��ַ 
};
//���������洢���м�¼������IP�����Ϣ
vector <UrlAndIp> tables;


//���������е���Ϣ���뻺���ļ�dns.txt�� 
void out_file(void)
{
	ofstream fileout("dns.txt");
	if (!fileout.is_open())
	{
		cout << "�ļ��򿪴���" << endl;
	}
	//����¼��������д���ļ���
	fileout << tables.size() << endl;
	//�������ļ���д��ÿ����¼
	for (int i = 0; i < tables.size(); i++)
	{
		fileout << tables.at(i).status << endl;
		fileout << tables.at(i).time << endl;
		fileout << tables.at(i).url << endl;
		fileout << tables.at(i).ip << endl;
	}
	//�ر��ļ�
	fileout.close();
	return;
}

//���ù���ʱ��
void set_expire(int* expire_time, int ttl)
{
	time_t now_time;
	now_time = time(NULL);
	*expire_time = now_time + ttl;//����ʱ��=��ǰʱ��+������
}

//��ʼ������ԭ�ļ�����Ϣ��������
void init_transtable(void)
{
	UrlAndIp urlAndip;

	//��Ԥ�ȴ��ڵ��ļ�dnsrelay.txt
	ifstream filein(fileName);
	if (!filein.is_open())
	{
		cout << "�ļ��򿪴���" << endl;
	}
	while (!filein.eof())
	{
		urlAndip.status = 1;	//������¼��Ч 
		urlAndip.time = 0;		//����ʱ��Ϊ������ 
		filein >> urlAndip.ip;	//��ȡip�ַ��� 
		filein >> urlAndip.url;	//��ȡurl�ַ��� 
		tables.push_back(urlAndip);	//�������� 
	}
	filein.close();
	//���������е�����������ļ���
	out_file();
	return;
}

//���ĳ����¼�Ƿ�ʱ
int is_expired(int expire_time)
{
	//0����ʱ��������
	if (expire_time == 0)
	{	//����0��ʾδ��ʱ
		return 0;
	}
	else
	{
		time_t now_time;
		now_time = time(NULL);
		if (now_time > expire_time)
		{
			return 1;//��ʱ����1
		}

		return 0;//δ��ʱ����0
	}
}

//�¼���һ����¼
void add_record(char* url, char* addr1, int ttl)
{
	int num_record = tables.size();
	UrlAndIp urlAndip;
	string addr = addr1;

	//�����¼��Ҫд���λ��
	int url_pos = -1, expired_pos = -1, empty_pos = -1;
	for (int i = 0; i < num_record; i++)
	{
		int expire_time = tables.at(i).time;
		if (tables.at(i).url == url)
		{
			//�����������ҵ������url
			url_pos = i;
			//ֱ��break,׼�����������¼
			break;
		}
		else if (tables.at(i).status == 0 && empty_pos == -1)
		{	//�����������ҵ�����Ч��¼
			empty_pos = i;
		}
		else
		{
			if (is_expired(expire_time) == 1)	//�Ƿ�ʱ
			{
				//����ǳ�ʱ��¼���������λ�ã�׼���滻�����¼
				expired_pos = i;
				break;
			}
		}
	}

	if (url_pos < 0)//��ʾ����������û���ҵ���ͬ��url
	{
		if (expired_pos >= 0)	//�ҵ����ѳ�ʱ��λ��
		{
			//���µļ�¼�滻��ʱ��¼������
			tables.at(expired_pos).status = 1;	//������¼��Ч 
			tables.at(expired_pos).url = url;	//����url�ַ���
			tables.at(expired_pos).ip = addr;	//����ip�ַ���
			set_expire(&tables.at(expired_pos).time, ttl);	//���ù���ʱ��
		}
		else if (empty_pos >= 0)	//�ҵ�����Ч��¼
		{
			//���µļ�¼�滻��Ч��¼������
			tables.at(empty_pos).status = 1;	//������¼��Ч 
			tables.at(empty_pos).url = url;		//����url�ַ���
			tables.at(empty_pos).ip = addr;		//����ip�ַ���
			set_expire(&tables.at(empty_pos).time, ttl);//���ù���ʱ��
		}
		else
		{	//����������δ�ҵ�url��û�г�ʱ����Ч�ļ�¼
			//����tablesĩβ�²���һ����¼
			UrlAndIp urlAndip;		//�¶����Ӧ��
			urlAndip.status = 1;	//������¼��Ч 
			urlAndip.ip = addr;		//����ip�ַ��� 
			urlAndip.url = url;		//����url�ַ��� 
			set_expire(&urlAndip.time, ttl);//���ù���ʱ��
			tables.push_back(urlAndip);	//�������� 
		}
	}
	else
	{	//�ҵ�����ͬ��url,����������¼
		tables.at(url_pos).status = 1;	//������¼��Ч 
		tables.at(url_pos).url = url;	//����url�ַ���
		tables.at(url_pos).ip = addr;	//����ip�ַ���
		set_expire(&tables.at(url_pos).time, ttl);//���ù���ʱ��
	}
	out_file();
}

//����������ѯIP��ַ
ip_addr get_ip(char* query_url)
{
	ip_addr result;
	result.addr[0] = { 0 };//��ʼ�����洢���
	int num_record;
	UrlAndIp urlAndip;
	num_record = tables.size();
	//���Բ���url��λ��
	int url_index = -1;
	for (int i = 0; i < num_record; i++)
	{
		//���������в������url
		if (tables.at(i).url == query_url)
		{
			url_index = i;
			if (debug_level == 2)
			{
				printf("������Ϣ���ļ���λ�ڵ�%d��\n", (url_index + 1));
			}
			if (is_expired(tables.at(i).time) == 1)//�ѹ���
			{
				tables.at(i).status = 0;//״̬��Ϊ��Ч
				if (debug_level == 2)
				{
					printf("�ü�¼�ѹ��ڣ�����\n");
				}
				result.addr[0] = 'e';
				out_file();
				return result;
			}
			break;
		}
	}
	if (url_index == -1)//û���ҵ����url,���ز��ҽ������δ�ҵ�
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