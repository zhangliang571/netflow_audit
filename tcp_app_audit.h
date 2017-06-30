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
	//when tcp connect close/shutdown, erase the data which keep in app session
	virtual int erase_auditid(uint64_t id){}

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

typedef enum _SSH_LOGIN_STATUS
{
	ENUM_SSH_LOGIN_NULL = 0,
	ENUM_SSH_LOGIN_VER_C_EXCHANGE,
	ENUM_SSH_LOGIN_VER_S_EXCHANGE,
	ENUM_SSH_LOGIN_KEX_C,
	ENUM_SSH_LOGIN_KEX_S,
	ENUM_SSH_LOGIN_DH_KEX_C,
	ENUM_SSH_LOGIN_DH_KEX_S,
	ENUM_SSH_LOGIN_GEX_REQ,
	ENUM_SSH_LOGIN_GEX_GROUP,
	ENUM_SSH_LOGIN_GEX_INIT,
	ENUM_SSH_LOGIN_GEX_REPLY,
	ENUM_SSH_LOGIN_NEW_KEY,
	ENUM_SSH_LOGIN_SESSION,
}SSH_LOGIN_STATUS;

typedef enum _TELNET_LOGIN_STATUS
{
	ENUM_TELNET_LOGIN_NULL = 0,
	ENUM_TELNET_LOGIN_USER,
	ENUM_TELNET_LOGIN_USER_RN,
	ENUM_TELNET_LOGIN_PASSWD,
	ENUM_TELNET_LOGIN_PASSWD_RN,
	ENUM_TELNET_LOGIN_SESSION,
}TELNET_LOGIN_STATUS;

typedef enum _FTP_LOGIN_STATUS
{
	ENUM_FTP_LOGIN_NULL = 0,
	ENUM_FTP_LOGIN_SERVICE_READY,
	ENUM_FTP_LOGIN_USER,
	ENUM_FTP_LOGIN_USEROK,
	ENUM_FTP_LOGIN_PASSWD,
	ENUM_FTP_LOGIN_LOGININ,
	ENUM_FTP_LOGIN_SESSION,

}FTP_LOGIN_STATUS;


struct key_exchange_hdr
{
	uint32_t pktlen;
	uint8_t paddinglen;
	uint8_t msgcode;
};

class CHttpAudit:public CTcpBaseAudit
{
public:
	CHttpAudit();
	virtual ~CHttpAudit();
	int audit(const void *hdr,int hdrlen,stTblItem &item,int dir);
	int erase_auditid(uint64_t id);
private:
};


class CSshAudit:public CTcpBaseAudit
{
public:
	CSshAudit();
	virtual ~CSshAudit();
	int audit(const void *hdr,int hdrlen,stTblItem &item,int dir);
	int erase_auditid(uint64_t id);
private:
	bool regex_match_verex_login(char *str,int strlen);
	int parse_login(uint64_t id,char *str,int strlen,int dir);
private:

	int _dir;
	enum _DH_KEY_MOD
	{
		DH_KEX,
		DH_GEX,
	};
	int _dh_key_mode;
	#define REG_VER_EX  ("SSH-(\\d+).(\\d+)-.*")
	#define SSH_MSG_KEYINIT 20
	#define SSH_MSG_NEWKEYS 21
	#define SSH_MSG_DHKEX_INIT 30
	#define SSH_MSG_DHKEX_REPLY 31
	#define SSH_MSG_DHGEX_REQUEST 34
	#define SSH_MSG_DHGEX_GROUP 31
	#define SSH_MSG_DHGEX_INIT 32
	#define SSH_MSG_DHGEX_REPLY 33


	//key is audit
	map<uint64_t,int> _mSshSes;
};

class CTelnetAudit:public CTcpBaseAudit
{
public:
	CTelnetAudit();
	virtual ~CTelnetAudit();
	int audit(const void *hdr,int hdrlen,stTblItem &item,int dir);
	int erase_auditid(uint64_t id);
private:
	bool regex_match_login(char *str,int strlen);
	bool regex_match_passwd(char *str,int strlen);
	bool match_login_rn(char *str,int strlen);
	int parse_login(uint64_t id,char *str,int strlen,int dir);
private:
	int _dir;
	#define REG_LOGIN  (".*(( login: .*)|( User: .*)|( Username: .*))")
	#define REG_PASSWD ("((\r\nPassword: .*)|(\r\npassword: .*))")

	//key is audit
	map<uint64_t,int> _mTelnetSes;
};


class CFtpAudit:public CTcpBaseAudit
{
public:
	CFtpAudit();
	virtual ~CFtpAudit();
	int audit(const void *hdr,int hdrlen,stTblItem &item,int dir);
	int erase_auditid(uint64_t id);
private:
	bool regex_match_strreg(char *str,string streg, int strlen);
	int parse_login(uint64_t id,char *str,int strlen,int dir);
private:
	#define REG_LOGIN_READY ("(220 ).*( FTP server ).*(ready.\r\n).*")
	#define REG_LOGIN_USER   ("(USER ).*(\r\n).*")
	#define REG_LOGIN_USEROK ("(331 ).*(\r\n).*")
	#define REG_LOGIN_PASSWD ("(PASS ).*(\r\n).*")
	#define REG_LOGIN_LOGININ ("(230 ).*(\r\n).*")
	//key is audit
	map<uint64_t,int> _mFtpSes;
};








#endif
