#ifndef INC_FILE_H
#define INC_FILE_H
#include <string>
#include <stdio.h>
#include<stdlib.h>
using namespace std;


typedef struct {
	char addr[16];
}ip_addr;


void init_transtable(void);

void add_record(char* url, char* addr1, int ttl);
ip_addr get_ip(char* query_url);


#endif

