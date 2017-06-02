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
	int load_msession_2_file(string strfile);
private:
	friend void coll_pcap_handle(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* pkt);
	int init();
	void zero_stTblItem(stTblItem &item);
	void zero_stTblItem();
	pcap_t* open_pcap(const char *dev);
	void close_pcap(pcap_t *pd);
	int swap_msessionEnd(map<string,stTblItem> &dstm);
	int insert_2_msessionEnd(string &key, stTblItem &item);
	int load_msession_2_ofstream(ofstream& of,map<string,stTblItem> &m);
	int ether_layer_parse(u_short ether_type, const u_char* p, u_int length);
	int ip_layer_parse(const u_char* p, u_int length);
private:
	string _strdev;
	pcap_t *_pd;
	sem_t _sem;
	uint64_t _totalN;
	
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
};

#endif

