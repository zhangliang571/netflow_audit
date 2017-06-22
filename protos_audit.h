#ifndef __PROTOS_AUDIT_H__
#define __PROTOS_AUDIT_H__
#include <map>
#include <semaphore.h>
#include "base.h"

enum E_AUDIT_FTYPE
{
	ENUM_AUDIT_TCP = 0,
	ENUM_AUDIT_UDP,
	ENUM_AUDIT_ICMP,
	ENUM_AUDIT_ARP,
	ENUM_AUDIT_TOT,
};


//parent class
class CBaseAudit
{
public:
	CBaseAudit();
	virtual string name(){}
	virtual ~CBaseAudit();
	virtual int audit(const void *hdr, stTblItem &item){}
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
	int audit(const void *hdr, stTblItem &item);
	int get_mTblItem_fin(multimap<string,stTblItem> &dstm);
	int get_mTblItem_fintimeout(map<string,stTblItem> &dstm);

private:
	sem_t _sem;

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
	int audit(const void *hdr, stTblItem &item);
	int get_mTblItem_fin(multimap<string,stTblItem> &dstm);
	int get_mTblItem_fintimeout(map<string,stTblItem> &dstm);
private:
	sem_t _sem;
};

//icmp audit
class CIcmpAudit:public CBaseAudit
{
public:
	CIcmpAudit();
	virtual ~CIcmpAudit();
	string name(){return "CIcmpAudit";}
	int audit(const void *hdr, stTblItem &item);
	int get_mTblItem_fin(multimap<string,stTblItem> &dstm);
	int get_mTblItem_fintimeout(map<string,stTblItem> &dstm);
private:
	sem_t _sem;
};

//icmp audit
class CArpAudit:public CBaseAudit
{
public:
	CArpAudit();
	virtual ~CArpAudit();
	string name(){return "CArpAudit";}
	int audit(const void *hdr, stTblItem &item);
	int get_mTblItem_fin(multimap<string,stTblItem> &dstm);
	int get_mTblItem_fintimeout(map<string,stTblItem> &dstm);
private:
	sem_t _sem;
};





#endif
