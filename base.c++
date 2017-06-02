#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <assert.h>
#include <cstring>
#include <dirent.h>
#include <boost/lexical_cast.hpp>
#include "base.h"


using namespace boost;

void _hex_dump(const u_char *p,int len)
{
	int i=0;
	for(;i<len;i++)
	{
		printf("%02x ",p[i]);
		if((i+1)%16  == 0)
			cout<<endl;
	}
	cout<<endl;
}

string inaddr_2_ip(uint32_t addr)
{
	char *ip = NULL;
	struct in_addr inaddr;
	inaddr.s_addr = addr;//htonl
	ip = inet_ntoa(inaddr);
	return string(ip);
}

//return : "20170526171212"
string get_current_time(const char *pfmt)
{
	struct tm *ptm;
	char nowtime[32] = {0};
	time_t t;

	assert(pfmt != NULL);
	t = time(NULL);
	ptm =localtime(&t);
	strftime(nowtime,sizeof(nowtime),pfmt,ptm);
	return nowtime;
}

int get_save_file_name(string strPath,string strTbl,string &strTempFile,string &strFile)
{
	string strDate;
	int pid;
	static uint64_t g_savefilenum = 0;

	if(access(SAVE_TEMP_FILE,F_OK) != 0)
		mkdir(SAVE_TEMP_FILE,0777);
	g_savefilenum++;
	pid = getpid();
	strDate = get_current_time(DATE_FORMAT);
	strTempFile = strPath + "temp/" + strTbl + "." + strDate + lexical_cast<string>(g_savefilenum) + lexical_cast<string>(pid);
	strFile = strPath + strTbl + "." + strDate + lexical_cast<string>(g_savefilenum) + lexical_cast<string>(pid);
	return 0;
}

/*
 * suffix like ".txt"
 */
int ls_dir(string strPath,const char *pfilter,const char *suffix,vector<string> &v)
{
	DIR *pdir = NULL;
	struct dirent *entry = NULL;
	string filename;

	pdir = opendir(strPath.c_str());
	if(pdir == NULL)
		return -1;
	while(entry=readdir(pdir))
	{
		filename = entry->d_name;
		if(suffix != NULL)
		{
			if(filename.substr(filename.find_last_of('.')+1) != string(suffix))
				continue;
		}
		if(pfilter != NULL)
		{
			if(filename.find(pfilter) == string::npos)
				continue;
		}
		if(filename[0] != '.')
			v.push_back(strPath+filename);
	}
	return v.size();
}
