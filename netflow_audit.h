#ifndef __NETFLOW_AUDIT_H__
#define __NETFLOW_AUDIT_H__

#include <string>


using namespace std;
struct framehdr
{
	u_char dstmac[6];
	u_char srcmac[6];
	uint16_t ftype;
};

typedef struct _stTblItem
{
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
}stTblItem;

#endif

