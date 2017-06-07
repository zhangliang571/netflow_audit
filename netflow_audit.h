#ifndef __NETFLOW_AUDIT_H__
#define __NETFLOW_AUDIT_H__

#include <string>
#include <map>
#include "base.h"
#include "protos_audit.h"

using namespace std;

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

typedef struct _timeoutList
{
	uint64_t timestamp;
	string key;
}TimeoutList;

struct framehdr
{
	u_char dstmac[6];
	u_char srcmac[6];
	uint16_t ftype;
};

class CNetflowAudit
{
public:
	CNetflowAudit();
	CNetflowAudit(const char *dev);
	~CNetflowAudit();
	void Run();
	void echo_msession();
	int load_mTimeout_2_file(string strfile);
private:
	friend void coll_pcap_handle(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* pkt);
	int init();
	int mount_baseaudit();
	int umount_baseaudit();
	void _zero_stTblItem();
	pcap_t* open_pcap(const char *dev);
	void close_pcap(pcap_t *pd);
	int load_tblitem_2_ofstream(ofstream& of,map<string,stTblItem> &m);
	int ether_layer_parse(u_short ether_type, const u_char* p, u_int length);
	int ip_layer_parse(const u_char* p, u_int length);
private:
	string _strdev;
	pcap_t *_pd;
	
	//one pcap stTblItem data
	stTblItem _tmpitem;

	vector<CBaseAudit*> _vCBaseAudit;


	vector<TimeoutList> _vTL;
};

#endif

