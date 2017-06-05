#ifndef __NETFLOW_AUDIT_H__
#define __NETFLOW_AUDIT_H__

#include <string>

#include <semaphore.h>

using namespace std;


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

char g_session_state[ENUM_STATE_TOTAL-1][32] = 
{
	"connnect req",
	"connnect rsp",
	"client close half",
	"server close half",
	"close success",
	"tcp rst",
	"udp",
	"icmp echo",
	"icmp unreach",
	"icmp redirect",
	"icmp timpstamp",
	"icmp address",
};

struct framehdr
{
	u_char dstmac[6];
	u_char srcmac[6];
	uint16_t ftype;
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
	string sip;
	string dip;
	u_short sport;
	u_short dport;
	u_long reqflow;
	u_long rspflow;
	int sessionstate;
	string auditext1;
	string auditext2;
}stTblItem;

class CNetflowAudit
{
public:
	CNetflowAudit();
	CNetflowAudit(const char *dev);
	~CNetflowAudit();
	void Run();
	void echo_msession();
	int load_mSessionEnd_2_file(string strfile);
	int load_mSessionTimeOut_2_file(string strfile);
	int load_mUDP_2_file(string strfile);
	int load_mICMP_2_file(string strfile);
private:
	friend void coll_pcap_handle(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* pkt);
	int init();
	void zero_stTblItem(stTblItem &item);
	void zero_stTblItem();
	pcap_t* open_pcap(const char *dev);
	void close_pcap(pcap_t *pd);
	int swap_mSessionEnd(map<string,stTblItem> &dstm);
	int swap_mSessionTimeOut(map<string,stTblItem> &dstm);
	int swap_mUDP(map<string,stTblItem> &dstm);
	int swap_mICMP(map<string,stTblItem> &dstm);
	int insert_2_mSessionEnd(string &key, stTblItem &item);
	int insert_2_mSessionTimeOut(string &key, stTblItem &item);
	int erase_mSessionTimeOut(string key);
	int load_tblitem_2_ofstream(ofstream& of,map<string,stTblItem> &m);
	int ether_layer_parse(u_short ether_type, const u_char* p, u_int length);
	int ip_layer_parse(const u_char* p, u_int length);
private:
	string _strdev;
	pcap_t *_pd;
	sem_t _sem;
	uint64_t _totalSession;
	uint64_t _totalUDP;
	uint64_t _totalICMP;
	
	//one pcap stTblItem data
	stTblItem _tmpitem;
	enum STREAM_DIR
	{
		ENUM_REQ = 1,
		ENUM_RSP,
	};
	enum STREAM_DIR _dir;

	//key is sip:sport:dip:dport
	map<string,stTblItem> _mSession;
	map<string,stTblItem> _mSessionEnd;
	//status of just req and half close is timeout 
	map<string,stTblItem> _mSessionTimeOut;
	//key is sip:sport:dip:dport
	map<string,stTblItem> _mUDP;
	//key is dmac:smac:sip:dip:type
	map<string,stTblItem> _mICMP;
};

#endif

