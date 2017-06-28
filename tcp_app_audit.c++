#include <iostream>
#include <arpa/inet.h>
#include "tcp_app_audit.h"
using namespace std;


CHttpAudit::CHttpAudit()
{

}
CHttpAudit::~CHttpAudit()
{

}
int CHttpAudit::audit(const void *hdr, int hdrlen, stTblItem &item,int dir)
{
	int ret = -1;
	cout<<"CHttpAudit::audit()\n";
	return ret;
}
//return: 0 -- find this id; else no 
int CHttpAudit::erase_auditid(uint64_t id)
{
	int ret = -1;
	return ret;
}



CSshAudit::CSshAudit()
{

}
CSshAudit::~CSshAudit()
{
	_mSshSes.clear();
}

/*
 * return: >=0 -- is ssh session; <0 no ssh session
 */
int CSshAudit::audit(const void *hdr, int hdrlen, stTblItem &item,int dir)
{
	char *p = (char*)hdr;
	int ret = 0;
	#if DEBUG
	cout<<"CSshAudit::audit()\n";
	_hex_dump(p,hdrlen);
	#endif
	ret = parse_login(item.auditid,p,hdrlen);
	if(ret == 1)
	{
		item.apptype = ENUM_TCP_SSH;
		item.ftypename = "TCP~SSH";
	}
	return ret;
}

//return: 0 -- find this id; else no 
int CSshAudit::erase_auditid(uint64_t id)
{
	int ret = -1;
	map<uint64_t,int>::iterator itm;
	if((itm=_mSshSes.find(id)) != _mSshSes.end())
	{
		ret = 0;
		_mSshSes.erase(itm);
	}
	return ret;
}

/*  
 * func: regex match ssh version exchange login
 * return: true or false
 */
bool CSshAudit::regex_match_verex_login(char *str,int strlen)
{
	bool ret = false;
	if(str==NULL || strlen<=0)
		return false;

	regex reg(REG_VER_EX);
	if(regex_match(str,reg))	
		ret = true;
	else 
		ret = false;
	return ret;
}
/*
 * ssh login handle:
 * 	client ver_exchange ------> server;
 * 	server ver_exchange ------> client;
 * 	client key_exchange_init ------> server;
 * 	server key_exchange_init ------> client;
 * 	client DHkey_exchange_init ------> server;
 * 	server DHkey_exchange_init; New_Keys ------> client;
 * 	client New_Keys     -------> server
 *
 * return: -1 -- no match ssh login; 1 -- finish login success; 0 -- login handling
 */
int CSshAudit::parse_login(uint64_t auditid,char *str,int strlen)
{
	int ret = -1;
	map<uint64_t,int>::iterator itm;

	if((itm=_mSshSes.find(auditid)) == _mSshSes.end())
	{
		if(regex_match_verex_login(str,strlen))
		_mSshSes[auditid] = ENUM_SSH_LOGIN_VER_C_EXCHANGE;
		else
		ret = -1;
	}
	else
	{

		ret = 0;
		switch(itm->second)
		{
			case ENUM_SSH_LOGIN_VER_C_EXCHANGE:
				if(regex_match_verex_login(str,strlen))
					itm->second += 1;
				else
					ret = -1;
				break;
			case ENUM_SSH_LOGIN_VER_S_EXCHANGE:
			case ENUM_SSH_LOGIN_KEX_C:
				{
					struct key_exchange_hdr *keh;
					keh = (struct key_exchange_hdr*)str;
					if(keh->msgcode == SSH_MSG_KEYINIT)
						itm->second += 1;
					else
						ret = -1;

				}
				break;
			case ENUM_SSH_LOGIN_KEX_S:
				{
					struct key_exchange_hdr *keh;
					keh = (struct key_exchange_hdr*)str;
					if(keh->msgcode == SSH_MSG_KEXDH_INIT)
						itm->second += 1;
					else
						ret = -1;

				}
				break;
			case ENUM_SSH_LOGIN_DH_KEX_C:
				{
					struct key_exchange_hdr *keh;
					char *pkeh = NULL;
					keh = (struct key_exchange_hdr*)str;
					if(keh->msgcode == SSH_MSG_KEXDH_REPLY)
					{
					pkeh = (char*)(str + 4 + ntohl(keh->pktlen));
					keh = (struct key_exchange_hdr*)(pkeh);
					if(keh->msgcode == SSH_MSG_NEWKEYS)
						itm->second += 1;
					else
						ret = -1;

					}
				}
				break;
			case ENUM_SSH_LOGIN_DH_KEX_S:
				{
					struct key_exchange_hdr *keh;
					keh = (struct key_exchange_hdr*)str;
					if(keh->msgcode == SSH_MSG_NEWKEYS)
					{
						itm->second += 1;
					}
					else
					ret = -1;

				}
				break;
			case ENUM_SSH_LOGIN_NEW_KEY:
				//finish login success
				itm->second += 1;
				ret = 1;
				break;

			case ENUM_SSH_LOGIN_SESSION:
				ret = 1;
				break;
			default:
				ret = -1;
				break;
		}

		if(ret<0)
			_mSshSes.erase(itm);
	}
	return ret;
}



CTelnetAudit::CTelnetAudit()
{

}
CTelnetAudit::~CTelnetAudit()
{
	_mTelnetSes.clear();
}

/*
 * return: >=0 -- is telnet login; <0 no ssh session
 */
int CTelnetAudit::audit(const void *hdr, int hdrlen, stTblItem &item,int dir)
{
	int ret = -1;
	char *p = (char*)hdr;
	#if DEBUG
	cout<<"CTelnetAudit::audit()\n";
	cout<<"hex dump telnetAudit:"<<hdrlen<<endl;
	_hex_dump((uint8_t*)p,hdrlen);
	#endif
	
	ret = parse_login(item.auditid,p,hdrlen);
	if(ret == 1)
	{
		item.apptype = ENUM_TCP_TELNET;
		item.ftypename = "TCP~TELNET";
	}
	return ret;
}

//return: 0 -- find this id; else no 
int CTelnetAudit::erase_auditid(uint64_t id)
{
	int ret = -1;
	map<uint64_t,int>::iterator itm;
	if((itm=_mTelnetSes.find(id)) != _mTelnetSes.end())
	{
		ret = 0;
		_mTelnetSes.erase(itm);
	}
	return ret;
}
/*  
 * func: regex match telnet "login:"
 * return: true or false
 */
bool CTelnetAudit::regex_match_login(char *str,int strlen)
{
	bool ret = false;
	if(str==NULL || strlen<=0)
		return false;

	regex reg(REG_LOGIN);
	if(regex_match(str,reg))	
		ret = true;
	else 
		ret = false;
	return ret;
}
/*  
 * func: regex match telnet "Password"
 * return: true or false
 */
bool CTelnetAudit::regex_match_passwd(char *str,int strlen)
{
	bool ret = false;
	if(str==NULL || strlen<=0)
		return false;

	regex reg(REG_PASSWD);
	if(regex_match(str,reg))	
		ret = true;
	else 
		ret = false;
	return ret;
}
/*  
 * func: match telnet "\r\n" 
 * return: true or false
 */
bool CTelnetAudit::match_login_rn(char *str,int strlen)
{
	bool ret = false;
	if(str==NULL || strlen<2)
		return false;

	if(str[0]=='\r' && str[1]=='\n')
		ret = true;
	else 
		ret = false;
	return ret;
}

/*
 * telnet login handle:
 * 	server " login: " ------> client;
 * 	client ...        ------> server;
 * 	client "\r\n"     ------> server;
 * 	server "\r\nPassword: " > client;
 * 	client ...        ------> server;
 * 	client "\r\n"     ------> server;
 *
 * return: -1 -- no match ssh login; 1 -- finish login success; 0 -- login handling
 */
int CTelnetAudit::parse_login(uint64_t auditid,char *str,int strlen)
{
	int ret = -1;
	map<uint64_t,int>::iterator itm;

	if((itm=_mTelnetSes.find(auditid)) == _mTelnetSes.end())
	{
		if(regex_match_login(str,strlen))
		_mTelnetSes[auditid] = ENUM_TELNET_LOGIN_USER;
		else
		ret = -1;
	}
	else
	{
		ret = -1;
		switch(itm->second)
		{
			case ENUM_TELNET_LOGIN_USER:
			case ENUM_TELNET_LOGIN_PASSWD:
			case ENUM_TELNET_LOGIN_PASSWD_RN:
				if(match_login_rn(str,strlen))
					itm->second += 1;
				else
					ret = -1;
				break;
			case ENUM_TELNET_LOGIN_USER_RN:
				if(regex_match_passwd(str,strlen))
					itm->second += 1;
				else
					ret = -1;
				break;

			case ENUM_TELNET_LOGIN_SESSION:
				ret = 1;
				break;
			default:
				ret = -1;
				break;
		}
	}
	return ret;	
}


CFtpAudit::CFtpAudit()
{

}
CFtpAudit::~CFtpAudit()
{

}
int CFtpAudit::audit(const void *hdr, int hdrlen, stTblItem &item,int dir)
{
	int ret = -1;
	cout<<"CFtpAudit::audit()\n";
	return ret;
}

//return: 0 -- find this id; else no 
int CFtpAudit::erase_auditid(uint64_t id)
{
	int ret = -1;
	return ret;
}
