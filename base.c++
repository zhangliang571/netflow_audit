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
#include <sys/time.h>
#include "base.h"


using namespace boost;

void _hex_dump(const uint8_t *p,int len)
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

void _char_dump(const uint8_t *p,int len)
{
	int i=0;
	for(;i<len;i++)
	{
		if(isprint(p[i]))
		printf("%-2c ",p[i]);
		else
		printf("%-2c",'.');

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

//return : "1496592000"
string get_current_timestamp(void)
{
	struct timeval tv;
	gettimeofday(&tv,0);
	return lexical_cast<string>(tv.tv_sec);

}
uint64_t get_audit_id(uint64_t count)
{
	string id = get_current_timestamp() + lexical_cast<string>(count);
	return lexical_cast<uint64_t>(id);
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

uint64_t mac_2_int(uint8_t *mac,int len)
{
	uint64_t ul = 0;
	uint64_t ret = 0;
	for(int i=0;i<len;i++)
	{
		ul = (uint64_t)mac[i]<<(40-i*8);
		ret += ul;
	}
	return ret;
}
void zero_stTblItem(stTblItem &item)
{
	item.id = 0;
	item.auditid = 0;
	item.starttime = "";
	item.endtime = "";
	item.ethtype = -1;
	item.apptype = -1;
	item.ftypename = "";
	item.dmac = 0;
	item.smac = 0;
	item.sip = 0;
	item.dip = 0;
	item.sport = 0;
	item.dport = 0;
	item.reqflow = 0;
	item.rspflow = 0;
	item.sessionstate = 0;
	item.auditext1 = "";
	item.auditext2 = "";
}

long recurse_get_timeout_session(vector<struct _mngTimeout> &v, int low, int height, string &strkey)
{  
	long middle=(low+height)/2;  

	//cout<<__FUNCTION__<<" "<<low<<" "<<height<<endl;
	if(middle>=v.size()-1)    
	{
		//cout<<__FUNCTION__<<"a find:"<<middle<<" "<<strkey<<endl;
		return middle;            
	}

	if(low>height)  
	{  
		//cout<<"no find:"<<strkey<<endl;
		return -1;                
	}  
	if(v[middle].strMapkey<=strkey && v[middle+1].strMapkey>strkey)  
	{  
		//cout<<__FUNCTION__<<" find:"<<middle<<" "<<strkey<<endl;
		return middle;            
	}  
	else if(v[middle].strMapkey > strkey)    
	{  
		recurse_get_timeout_session(v,low,middle-1,strkey);  
	}  
	else if(v[middle].strMapkey <= strkey)   
	{  
		recurse_get_timeout_session(v,middle+1,height,strkey);  
	}  
}
