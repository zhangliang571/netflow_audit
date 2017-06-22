#ifndef __PROTOS_AUDIT_H__
#define __PROTOS_AUDIT_H__
#include <map>
#include <semaphore.h>
#include "base.h"

//parent class
class CBaseAudit
{
public:
	CBaseAudit();
	virtual string name(){}
	virtual ~CBaseAudit();
	virtual int audit(void *hdr, stTblItem &item){}
	virtual int get_mTblItem_fin(multimap<string,stTblItem> &dstm){}
	virtual int get_mTblItem_fintimeout(map<string,stTblItem> &dstm){}
	map<string,stTblItem> _mTblItem;

	enum STREAM_DIR _dir;
private:
};

//tcp audit 
class CTcpAudit:public CBaseAudit
{
public:
	CTcpAudit();
	virtual ~CTcpAudit();
	string name(){return "CTcpAudit";}
	int audit(void *hdr, stTblItem &item);
	int get_mTblItem_fin(multimap<string,stTblItem> &dstm);
	int get_mTblItem_fintimeout(map<string,stTblItem> &dstm);

private:
	sem_t _sem;
	uint64_t _totalTCP;

	map<string,stTblItem> _mSession;
	multimap<string,stTblItem> _mmSessionEnd;
	map<string,stTblItem> _mSessionTimeout;

	//manage tcp timeout session
	vector<struct _mngTimeout> _vSessionTimeout;
};

//udp audit
class CUdpAudit:public CBaseAudit
{
public:
	CUdpAudit();
	virtual ~CUdpAudit();
	string name(){return "CUdpAudit";}
	int audit(void *hdr, stTblItem &item);
	int get_mTblItem_fin(multimap<string,stTblItem> &dstm);
	int get_mTblItem_fintimeout(map<string,stTblItem> &dstm);
private:
	sem_t _sem;
	uint64_t _totalUDP;
};

//icmp audit
class CIcmpAudit:public CBaseAudit
{
public:
	CIcmpAudit();
	virtual ~CIcmpAudit();
	string name(){return "CIcmpAudit";}
	int audit(void *hdr, stTblItem &item);
	int get_mTblItem_fin(multimap<string,stTblItem> &dstm);
	int get_mTblItem_fintimeout(map<string,stTblItem> &dstm);
private:
	sem_t _sem;
	uint64_t _totalICMP;
};



#endif
