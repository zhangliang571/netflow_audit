#ifndef __TCP_APP_AUDIT_H__
#define __TCP_APP_AUDIT_H__
#include <iostream>
#include <string>
#include <boost/regex.hpp>
#include "base.h"

using namespace std;
using namespace boost;

//tcp parent class
class CTcpBaseAudit
{
public:
	CTcpBaseAudit(){}
	virtual ~CTcpBaseAudit(){}
	virtual int audit(const void *hdr, int hdrlen, stTblItem &item,int dir=0){}

private:

};


enum E_TCP_APP_TYPE
{
	ENUM_TCP_HTTP = 0,
	ENUM_TCP_SSH,
	ENUM_TCP_TELNET,
	ENUM_TCP_FTP,
	ENUM_TCP_TOT,
};
typedef enum _LOGIN_STATUS
{
	ENUM_LOGIN_NULL = 0,
	ENUM_LOGIN_VER_C_EXCHANGE,
	ENUM_LOGIN_VER_S_EXCHANGE,
	ENUM_LOGIN_KEX_C,
	ENUM_LOGIN_KEX_S,
	ENUM_LOGIN_DH_KEX_C,
	ENUM_LOGIN_DH_KEX_S,
	ENUM_LOGIN_NEW_KEY,
}E_LOGIN_STATUS;

struct key_exchange_hdr
{
	uint32_t pktlen;
	uint8_t paddinglen;
	uint8_t msgcode;
};

class CTelnetAudit:public CTcpBaseAudit
{
public:
	CTelnetAudit();
	virtual ~CTelnetAudit();
	int audit(const void *hdr,int hdrlen,stTblItem &item,int dir);
private:
};

class CSshAudit:public CTcpBaseAudit
{
public:
	CSshAudit();
	virtual ~CSshAudit();
	int audit(const void *hdr,int hdrlen,stTblItem &item,int dir);
private:
	bool regex_match_login(char *str,int strlen);
	int parse_login(uint64_t id,char *str,int strlen);
private:

	#define REG_VER_EX  ("SSH-(\\d+).(\\d+)-.*")
	#define SSH_MSG_KEYINIT 20
	#define SSH_MSG_NEWKEYS 21
	#define SSH_MSG_KEXDH_INIT 30
	#define SSH_MSG_KEXDH_REPLY 31

	map<uint64_t,int> _mSshSes;
};

class CFtpAudit:public CTcpBaseAudit
{
public:
	CFtpAudit();
	virtual ~CFtpAudit();
	int audit(const void *hdr,int hdrlen,stTblItem &item,int dir);
private:
};

class CHttpAudit:public CTcpBaseAudit
{
public:
	CHttpAudit();
	virtual ~CHttpAudit();
	int audit(const void *hdr,int hdrlen,stTblItem &item,int dir);
private:
};








#endif
