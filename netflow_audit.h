#ifndef __NETFLOW_AUDIT_H__
#define __NETFLOW_AUDIT_H__

#include <string>


using namespace std;


enum E_SESSION_STATE
{
	ENUM_SUCCESS = 1,
	ENUM_RST,
	ENUM_UDP,
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
	u_char dmac[6];
	u_char smac[6];
	string sip;
	string dip;
	u_short sport;
	u_short dport;
	u_long reqflow;
	u_long rsqflow;
	int sessionstate;
}stTblItem;

class CNetflowAudit
{
public:
	CNetflowAudit();
	CNetflowAudit(const char *dev);
	~CNetflowAudit();
	void Run();
private:
	friend void coll_pcap_handle(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* pkt);
	int init();
	pcap_t* open_pcap(const char *dev);
	void close_pcap(pcap_t *pd);
	int ether_layer_parse(u_short ether_type, const u_char* p, u_int length);
	int ip_layer_parse(const u_char* p, u_int length);
	void echo_tmpitem();
private:
	string _strdev;
	pcap_t *_pd;
	
	//one pcap stTblItem data
	stTblItem* _tmpitem;
};

#endif

