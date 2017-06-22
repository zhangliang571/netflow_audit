#ifndef __BASE_H___
#define __BASE_H___

#include <iostream>
#include <string>
#include <vector>
#include <inttypes.h>



using namespace std;

#define SAVE_FILE "/data/input/"
#define SAVE_TEMP_FILE "/data/input/temp/"
#define DATE_FORMAT "%y%m%d%H%M%S"
#define WDD_NETFLOW_AUDIT "wdd_netflow_audit"

//net.ipv4.tcp_keepalive_time
//#define TCP_TIMEOUT 7200
#define TCP_TIMEOUT 120
#define NO_CONNECT_TIMEOUT 120


enum STREAM_DIR
{
	ENUM_REQ = 1,
	ENUM_RSP,
};


enum E_SESSION_STATE
{
	ENUM_CONNECT_REQ = 1,
	ENUM_CONNECT_RSP,
	ENUM_CLIENT_CLOSE_HALF,
	ENUM_SERVER_CLOSE_HALF,
	ENUM_CLOSE_SUCCESS,
	ENUM_RST,
	ENUM_UDP,
	ENUM_ICMP_ECHO,
	ENUM_ICMP_DEST_UNREACH,
	ENUM_ICMP_REDIRECT,
	ENUM_ICMP_TIMESTAMP,
	ENUM_ICMP_ADDRESS,
	ENUM_STATE_TOTAL,
};


typedef struct _stTblItem
{
	int id;
	u_int auditid;
	string starttime;
	string endtime;
	string ftype;
	uint64_t dmac;
	uint64_t smac;
	uint64_t sip;
	uint64_t dip;
	u_short sport;
	u_short dport;
	u_long reqflow;
	u_long rspflow;
	int sessionstate;
	string auditext1;
	string auditext2;
}stTblItem;

struct _mngTimeout
{
	string strTime;
	string strMapkey;
};



void _hex_dump(const u_char *p,int len);
string inaddr_2_ip(uint32_t addr);
uint64_t get_audit_id(uint64_t count);
int get_save_file_name(string strPath,string strTbl,string &strTmpFile,string &strFile);
int ls_dir(string strPath,const char *pfilter,const char *suffix,vector<string> &v);
uint64_t mac_2_int(u_char* mac,int len);
void zero_stTblItem(stTblItem &item);
long recurse_get_timeout_session(vector<struct _mngTimeout> &v, int low, int height, string &strkey);

#endif
