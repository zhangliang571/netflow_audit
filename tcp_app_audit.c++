#include <iostream>
#include <arpa/inet.h>
#include "tcp_app_audit.h"
using namespace std;


CTelnetAudit::CTelnetAudit()
{

}
CTelnetAudit::~CTelnetAudit()
{
}

int CTelnetAudit::audit(const void *hdr, int hdrlen, stTblItem &item,int dir)
{
	cout<<"CTelnetAudit::audit()\n";
}



CSshAudit::CSshAudit()
{
}
CSshAudit::~CSshAudit()
{
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
		item.apptype = ENUM_TCP_SSH;
	return ret;
}

/*
 * return: -1 -- no match ssh login; 1 -- finish login success; 0 -- login handling
 */
int CSshAudit::parse_login(uint64_t auditid,char *str,int strlen)
{
	int ret = 0;
	map<uint64_t,int>::iterator itm;

	if((itm=_mSshSes.find(auditid)) == _mSshSes.end())
	{
		if(regex_match_login(str,strlen))
		_mSshSes[auditid] = ENUM_LOGIN_VER_C_EXCHANGE;
		else
		ret = -1;
	}
	else
	{

		switch(itm->second)
		{
			case ENUM_LOGIN_VER_C_EXCHANGE:
				if(regex_match_login(str,strlen))
					itm->second += 1;
				else
					ret = -1;
				break;
			case ENUM_LOGIN_VER_S_EXCHANGE:
			case ENUM_LOGIN_KEX_C:
				{
					struct key_exchange_hdr *keh;
					keh = (struct key_exchange_hdr*)str;
					if(keh->msgcode == SSH_MSG_KEYINIT)
						itm->second += 1;
					else
						ret = -1;

				}
				break;
			case ENUM_LOGIN_KEX_S:
				{
					struct key_exchange_hdr *keh;
					keh = (struct key_exchange_hdr*)str;
					if(keh->msgcode == SSH_MSG_KEXDH_INIT)
						itm->second += 1;
					else
						ret = -1;

				}
				break;
			case ENUM_LOGIN_DH_KEX_C:
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
			case ENUM_LOGIN_DH_KEX_S:
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
			case ENUM_LOGIN_NEW_KEY:
				//finish login success
				_mSshSes.erase(itm);
				ret = 1;
				break;

			default:
				ret = -1;
				break;
		}

		if(!ret)
			_mSshSes.erase(itm);
	}
	return ret;
}
/*  
 * func: regex match ssh version exchange login
 * return: true or false
 */
bool CSshAudit::regex_match_login(char *str,int strlen)
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


CFtpAudit::CFtpAudit()
{

}
CFtpAudit::~CFtpAudit()
{
}

int CFtpAudit::audit(const void *hdr, int hdrlen, stTblItem &item,int dir)
{
	cout<<"CFtpAudit::audit()\n";
}

CHttpAudit::CHttpAudit()
{

}
CHttpAudit::~CHttpAudit()
{
}

int CHttpAudit::audit(const void *hdr, int hdrlen, stTblItem &item,int dir)
{
	cout<<"CHttpAudit::audit()\n";
}

