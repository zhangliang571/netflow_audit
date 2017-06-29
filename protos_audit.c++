#include <boost/lexical_cast.hpp>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <cassert>
#include <semaphore.h>
#include "protos_audit.h"
#include "proto_type.h"
#include "base.h"
#include "date_time.h"
#include "tcp_app_audit.h"

using namespace boost;
extern uint64_t g_total_audit;

CBaseAudit::CBaseAudit()
{

}
CBaseAudit::~CBaseAudit()
{
	_mTblItem.clear();
}


CTcpAudit::CTcpAudit()
{
	sem_init(&_sem,0,1);
	mount_app_layer();
}
CTcpAudit::~CTcpAudit()
{
	_mSession.clear();
	_mmSessionEnd.clear();
	_mSessionTimeout.clear();
	_vSessionTimeout.clear();
	sem_destroy(&_sem);
	umount_app_layer();
}
int CTcpAudit::mount_app_layer(void)
{
	CHttpAudit *phttp     = new CHttpAudit;
	CSshAudit *pssh       = new CSshAudit;
	CTelnetAudit *ptelnet = new CTelnetAudit;
	CFtpAudit *pftp       = new CFtpAudit;
	_aCTcpAppAudit[ENUM_TCP_HTTP]   = phttp;
	_aCTcpAppAudit[ENUM_TCP_SSH]    = pssh;
	_aCTcpAppAudit[ENUM_TCP_TELNET] = ptelnet;
	_aCTcpAppAudit[ENUM_TCP_FTP]    = pftp;
}
void CTcpAudit::umount_app_layer(void)
{
	for(int i=0;i<ENUM_TCP_TOT;i++)
		if(_aCTcpAppAudit[i] != NULL)
		delete _aCTcpAppAudit[i];
}

//strkey is _mSession key
int CTcpAudit::erase_session(string strkey)
{
	int ret = -1;
	uint64_t id;

	map<string,stTblItem>::iterator itm;
	if((itm=_mSession.find(strkey)) != _mSession.end())
	{
		id = itm->second.auditid;
		for(int i=0;i<ENUM_TCP_TOT;i++)
		{
			ret = _aCTcpAppAudit[i]->erase_auditid(id);
			if(ret==0)
				break;
		}

		_mSession.erase(itm);
	}
	return ret;
}

int CTcpAudit::audit(const void *hdr, int hdrlen, stTblItem &item,int dir)
{
	assert(hdr != NULL);
	int ret = 0;
	struct tcphdr *tcph = NULL;
	uint16_t sport,dport;
	int appdatalen = 0;
	char *pappdata = NULL;
	map<string,stTblItem>::iterator itm ;
	string key;
	struct _mngTimeout vmng;

	tcph = (struct tcphdr*)((u_char*)hdr);
	sport = ntohs(tcph->source);
	dport = ntohs(tcph->dest);

	//tcp connect rst
	if(tcph->rst == 1 && tcph->ack==1)
	{
		_dir = ENUM_RSP;
		key = lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport);

		if((itm=_mSessionTimeout.find(key)) != _mSessionTimeout.end())
		{
			sem_wait(&_sem);////////////////////////////////
			itm->second.endtime = item.starttime;
			itm->second.sessionstate = ENUM_RST;
			itm->second.rsppkts++;
			itm->second.rspflow += item.reqflow;
			_mmSessionEnd.insert(pair<string,stTblItem>(key,_mSessionTimeout[key]));

			_mSessionTimeout.erase(itm);
			vector<struct _mngTimeout>::iterator itv;
			for(itv=_vSessionTimeout.begin();itv!=_vSessionTimeout.end();itv++)
			{
				if(itv->strMapkey == key)
				{
					_vSessionTimeout.erase(itv);	
					break;
				}
			}
			sem_post(&_sem);////////////////////////////////
		}
		else if((itm=_mSession.find(key)) != _mSession.end())
		{
			itm->second.endtime = item.starttime;
			itm->second.sessionstate = ENUM_RST;
			itm->second.rsppkts++;
			itm->second.rspflow += item.reqflow;
			sem_wait(&_sem);////////////////////////////////
			_mmSessionEnd.insert(pair<string,stTblItem>(key,itm->second));
			sem_post(&_sem);////////////////////////////////
			erase_session(key);
		}

	}	
	//req 3 handshakes
	else if(tcph->syn == 1 && tcph->ack==0 && tcph->ece==0&&tcph->cwr==0)
	{
		_dir = ENUM_REQ;
		key = lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport);
		sem_wait(&_sem);////////////////////////////////
		if((itm=_mSessionTimeout.find(key)) == _mSessionTimeout.end())
		{
			g_total_audit++;
			item.auditid = get_audit_id(g_total_audit);
			item.starttime = item.starttime;
			item.endtime = "";
			item.ethtype = ENUM_AUDIT_ETHTYPE_TCP;
			item.ftypename = "TCP";
			item.sport = sport;
			item.dport = dport;
			item.reqpkts = 1;
			item.rsppkts = 0;
			item.reqflow = item.reqflow;
			item.rspflow = 0;
			item.sessionstate = ENUM_CONNECT_REQ;

			_mSessionTimeout[key] =  item;

			vmng.strTime = item.starttime;
			vmng.strMapkey = key;
			_vSessionTimeout.push_back(vmng);
		}
		//new connect at half close
		else
		{
			//if(itm->second.sessionstate == ENUM_CLIENT_CLOSE_HALF || itm->second.sessionstate==ENUM_SERVER_CLOSE_HALF)
			{
				g_total_audit++;
				_mmSessionEnd.insert(pair<string,stTblItem>(key,itm->second));
				_mSessionTimeout.erase(key);

				item.auditid = get_audit_id(g_total_audit);
				item.starttime = item.starttime;
				item.endtime = "";
				item.ethtype = ENUM_AUDIT_ETHTYPE_TCP;
				item.ftypename = "TCP";
				item.sport = sport;
				item.dport = dport;
				item.reqpkts = 1;
				item.rsppkts = 0;
				item.reqflow = item.reqflow;
				item.rspflow = 0;
				item.sessionstate = ENUM_CONNECT_REQ;

				_mSessionTimeout[key] =  item;

				vmng.strTime = item.starttime;
				vmng.strMapkey = key;
				_vSessionTimeout.push_back(vmng);
			}

		}
		sem_post(&_sem);////////////////////////////////
	}
	//rsp 3 handshakes
	else if(tcph->syn == 1 && tcph->ack==1)
	{
		_dir = ENUM_RSP;
		cout<<"rsp 3 handshakes ..............sip:"<<item.dip<<" sport:"<<dport<<" dip:"<<item.sip<<" dport:"<<sport<<endl;
		key = lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport);
		sem_wait(&_sem);////////////////////////////////
		if((itm=_mSessionTimeout.find(key)) != _mSessionTimeout.end())
		{
			itm->second.rsppkts = 1;
			itm->second.rspflow = item.reqflow;
			itm->second.sessionstate  = ENUM_CONNECT_RSP;		
			_mSession[key] = itm->second;
			_mSessionTimeout.erase(key);
		}
		sem_post(&_sem);////////////////////////////////
	}
	//tcp connect end
	else if(tcph->fin == 1 && tcph->ack==1)
	{
		cout<<"end  tcp connect...............sip:"<<item.sip<<" dip:"<<item.dip<<"sport:"<<sport<<" dport:"<<dport<<endl;
		key = lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport);
		sem_wait(&_sem);////////////////////////////////
		if((itm=_mSession.find(key)) != _mSession.end())
		{
			_dir = ENUM_REQ;
			if(itm->second.sessionstate == ENUM_SERVER_CLOSE_HALF)
			{
				itm->second.endtime = item.starttime;
				itm->second.reqpkts++;
				itm->second.reqflow += item.reqflow;
				itm->second.sessionstate  = ENUM_CLOSE_SUCCESS;		
				_mmSessionEnd.insert(pair<string,stTblItem>(key,itm->second));
				erase_session(key);
				_mSessionTimeout.erase(key);

				vector<struct _mngTimeout>::iterator itv;
				for(itv=_vSessionTimeout.begin();itv!=_vSessionTimeout.end();itv++)
				{
					if(itv->strMapkey == key)
					{
						_vSessionTimeout.erase(itv);	
						break;
					}
				}
			}
			else
			{
				itm->second.endtime = item.starttime;
				itm->second.reqpkts++;
				itm->second.reqflow += item.reqflow;
				itm->second.sessionstate  = ENUM_CLIENT_CLOSE_HALF;		
				_mSessionTimeout[key] = itm->second;
				erase_session(key);
			}

		}
		else
		{
			key = lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport);
			if((itm=_mSession.find(key)) != _mSession.end())
			{
				_dir = ENUM_RSP;
				if(itm->second.sessionstate == ENUM_CLIENT_CLOSE_HALF)
				{
					itm->second.endtime = item.starttime;
					itm->second.rsppkts++;
					itm->second.rspflow += item.reqflow;
					itm->second.sessionstate  = ENUM_CLOSE_SUCCESS;		
					_mmSessionEnd.insert(pair<string,stTblItem>(key,itm->second));
					erase_session(key);
					_mSessionTimeout.erase(key);

					vector<struct _mngTimeout>::iterator itv;
					for(itv=_vSessionTimeout.begin();itv!=_vSessionTimeout.end();itv++)
					{
						if(itv->strMapkey == key)
						{
							_vSessionTimeout.erase(itv);	
							break;
						}
					}

				}
				else
				{
					itm->second.endtime = item.starttime;
					itm->second.rsppkts++;
					itm->second.rspflow += item.reqflow;
					itm->second.sessionstate  = ENUM_SERVER_CLOSE_HALF;		
					_mSessionTimeout[key] = itm->second;
					erase_session(key);
				}
			}

		}
		sem_post(&_sem);////////////////////////////////
	}
	else
	{
		appdatalen = hdrlen - tcph->doff*4;
		pappdata = (char*)((char*)hdr + tcph->doff*4);


		if(appdatalen > 0)
		{

		key = lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport);
		if((itm=_mSession.find(key)) != _mSession.end())
		{
			_dir = ENUM_REQ;
			itm->second.reqpkts++;
			itm->second.reqflow += item.reqflow;

			if(sport == 20 || dport == 20)
			{
				itm->second.apptype = ENUM_TCP_FTP;
				//ret = _aCTcpAppAudit[ENUM_TCP_FTP]->audit(pappdata,appdatalen,itm->second,_dir);
			}
			else if(sport == 21 || dport == 21)
			{
				//itm->second.apptype = ENUM_TCP_FTP;
				ret = _aCTcpAppAudit[ENUM_TCP_FTP]->audit(pappdata,appdatalen,itm->second,_dir);
			}
			else if(sport == 22 || dport == 22)
			{
				//itm->second.apptype = ENUM_TCP_SSH;
				ret = _aCTcpAppAudit[ENUM_TCP_SSH]->audit(pappdata,appdatalen,itm->second,_dir);
			}
			else if(sport == 23 || dport == 23)
			{
				//itm->second.apptype = ENUM_TCP_TELNET;
				ret = _aCTcpAppAudit[ENUM_TCP_TELNET]->audit(pappdata,appdatalen,itm->second,_dir);
			}
			else
			{
				//audit tcp app layer
				for(int i=0;i<ENUM_TCP_TOT;i++)
				{
					ret = _aCTcpAppAudit[i]->audit(pappdata,appdatalen,itm->second,_dir);
					if(ret>=0)
						break;
				}
			}
		}
		else
		{
			key = lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport);
			if((itm=_mSession.find(key)) != _mSession.end())
			{
				_dir = ENUM_RSP;
				itm->second.rsppkts++;
				itm->second.rspflow += item.reqflow;

				if(sport == 20 || dport == 20)
				{
					itm->second.apptype = ENUM_TCP_FTP;
					//ret = _aCTcpAppAudit[ENUM_TCP_FTP]->audit(pappdata,appdatalen,itm->second,_dir);
				}
				else if(sport == 21 || dport == 21)
				{
					//itm->second.apptype = ENUM_TCP_FTP;
					ret = _aCTcpAppAudit[ENUM_TCP_FTP]->audit(pappdata,appdatalen,itm->second,_dir);
				}
				else if(sport == 22 || dport == 22)
				{
					//itm->second.apptype = ENUM_TCP_SSH;
					ret = _aCTcpAppAudit[ENUM_TCP_SSH]->audit(pappdata,appdatalen,itm->second,_dir);
				}
				else if(sport == 23 || dport == 23)
				{
					//itm->second.apptype = ENUM_TCP_TELNET;
					ret = _aCTcpAppAudit[ENUM_TCP_TELNET]->audit(pappdata,appdatalen,itm->second,_dir);
				}
				else
				{
					//audit tcp app layer
					for(int i=0;i<ENUM_TCP_TOT;i++)
					{
						ret = _aCTcpAppAudit[i]->audit(pappdata,appdatalen,itm->second,_dir);
						if(ret>=0)
							break;
					}
				}
			}
		}

		}
	}

	return ret;
}

  
int CTcpAudit::get_mTblItem_fin(multimap<string,stTblItem> &dstm)
{
	int ret = 0;
	sem_wait(&_sem);
	dstm = _mmSessionEnd;
	_mmSessionEnd.clear();
	ret = dstm.size();
	sem_post(&_sem);
	return 	ret;
}
int CTcpAudit::get_mTblItem_fintimeout(map<string,stTblItem> &dstm)
{
	int ret = 0;
	long vn = -1;
	map<string,stTblItem>::iterator itm;
	CDateTime dtime;
	string strTimeout;
	string strkey;

	if(_vSessionTimeout.size() == 0)
	{
		return 0;
	}
	else
		;//cout<<"_vSessionTimeout "<<_vSessionTimeout.size()<<endl;

	strTimeout = dtime.before_current_time(TCP_TIMEOUT);
	
	vn = recurse_get_timeout_session(_vSessionTimeout, 0, _vSessionTimeout.size(), strTimeout);
	sem_wait(&_sem);////////////////////////////////
	if(vn > 0)
	{
		for(int i=0;i<=vn;i++)
		{
			strkey = _vSessionTimeout[i].strMapkey;
			if(_mSessionTimeout.find(strkey) != _mSessionTimeout.end())
			{
				//cout<<"tcp timeout session:"<<strkey<<endl;
				dstm[strkey] = _mSessionTimeout[strkey];
				_mSessionTimeout.erase(strkey);
			}
		}

		if(vn >= (_vSessionTimeout.size()-1))
			_vSessionTimeout.clear();
		else
			_vSessionTimeout.erase(_vSessionTimeout.begin(),_vSessionTimeout.begin()+vn+1);

		ret = dstm.size();
	}
	sem_post(&_sem);////////////////////////////////
	return 	ret;
}

CUdpAudit::CUdpAudit()
{
	sem_init(&_sem,0,1);
}
CUdpAudit::~CUdpAudit()
{
	sem_destroy(&_sem);
}
int CUdpAudit::audit(const void *hdr, int hdrlen, stTblItem &item,int dir)
{
	assert(hdr != NULL);
	int ret = 0;
	struct udphdr *udph = NULL;
	uint16_t sport,dport;
	string key;

	udph = (struct udphdr*)((u_char*)hdr);


	sport = ntohs(udph->source);
	dport = ntohs(udph->dest);

	key = lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport);


	sem_wait(&_sem);////////////////////////////////
	if(_mTblItem.find(key) == _mTblItem.end())
	{
		string keyrsp = lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport);
		if(_mTblItem.find(keyrsp) == _mTblItem.end())
		{
			_dir = ENUM_REQ;	
			g_total_audit++;
			item.auditid = get_audit_id(g_total_audit);
			item.starttime = item.starttime;
			item.endtime = "";
			item.ethtype = ENUM_AUDIT_ETHTYPE_UDP;
			item.ftypename = "UDP";
			item.sport = sport;
			item.dport = dport;
			item.reqpkts = 1;
			item.rsppkts = 0;
			item.reqflow = item.reqflow;
			item.rspflow = 0;
			item.sessionstate = ENUM_UDP;
			_mTblItem[key] = item;	

		}
		else
		{
			_dir = ENUM_RSP;	
			_mTblItem[keyrsp].rsppkts++;
			_mTblItem[keyrsp].rspflow += item.reqflow;
		}

	}
	else
	{
		_dir = ENUM_REQ;	
		_mTblItem[key].rsppkts++;
		_mTblItem[key].rspflow += item.reqflow;
	}
	sem_post(&_sem);////////////////////////////////

	return ret;
}

int CUdpAudit::get_mTblItem_fintimeout(map<string,stTblItem> &dstm)
{
	int ret = 0;
	sem_wait(&_sem);
	dstm = _mTblItem;
	_mTblItem.clear();
	ret = dstm.size();
	sem_post(&_sem);
	return 	ret;
}
int CUdpAudit::get_mTblItem_fin(multimap<string,stTblItem> &dstm)
{
	return 0;
}

CIcmpAudit::CIcmpAudit()
{
	sem_init(&_sem,0,1);
}
CIcmpAudit::~CIcmpAudit()
{
	sem_destroy(&_sem);
}
int CIcmpAudit::audit(const void *hdr, int hdrlen, stTblItem &item,int dir)
{
	assert(hdr != NULL);
	int ret = 0;
	struct icmphdr *icmph= NULL;
	uint8_t icmp_type;
	string key;

	icmph = (struct icmphdr*)((u_char*)hdr);

	sem_wait(&_sem);////////////////////////////////
	switch(icmph->type)
	{
		case ICMP_ECHO:
		case ICMP_DEST_UNREACH:
		case ICMP_REDIRECT:
		case ICMP_TIMESTAMP:
		case ICMP_ADDRESS:
			if(icmph->type == ICMP_ECHO)
				icmp_type = ENUM_ICMP_ECHO;
			else if(icmph->type == ICMP_DEST_UNREACH)
				icmp_type = ENUM_ICMP_DEST_UNREACH;
			else if(icmph->type == ICMP_REDIRECT)
				icmp_type = ENUM_ICMP_REDIRECT;
			else if(icmph->type == ICMP_TIMESTAMP)
				icmp_type = ENUM_ICMP_TIMESTAMP;
			else if(icmph->type == ICMP_ADDRESS)
				icmp_type = ENUM_ICMP_ADDRESS;
				

			//key is dmac:smac:sip:dip:type
			key = lexical_cast<string>(item.dmac)+":"+lexical_cast<string>(item.smac)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(icmp_type);

			if(_mTblItem.find(key) == _mTblItem.end())
			{
				g_total_audit++;
				item.auditid = get_audit_id(g_total_audit);
				item.starttime = item.starttime;
				item.endtime = "";
				item.ethtype = ENUM_AUDIT_ETHTYPE_ICMP;
				item.ftypename = "ICMP";
				//icmp no port, this item as icmp pkt count
				item.reqpkts = 1;
				item.rsppkts = 0;
				if(icmph->type == ICMP_ECHO)
				{
					item.reqflow = item.reqflow;
					item.rspflow = 0;
				}
				else if(icmph->type == ICMP_DEST_UNREACH)
				{
					item.reqflow = 0;
					item.rspflow = item.reqflow;
				}
				else if(icmph->type == ICMP_REDIRECT)
				{
					item.reqflow = 0;
					item.rspflow = item.reqflow;
				}
				else if(icmph->type == ICMP_TIMESTAMP)
				{
					item.reqflow = item.reqflow;
					item.rspflow = 0;
				}
				else if(icmph->type == ICMP_ADDRESS)
				{
					item.reqflow = item.reqflow;
					item.rspflow = 0;
				}
				item.sessionstate = icmp_type;
				_mTblItem[key] = item;	
			}
			else
			{
				_mTblItem[key].reqpkts++;	
				if(icmph->type == ICMP_ECHO)
				{
					_mTblItem[key].reqflow += item.reqflow;	
				}
				else if(icmph->type == ICMP_DEST_UNREACH)
				{
					_mTblItem[key].rspflow += item.reqflow;	
				}
				else if(icmph->type == ICMP_REDIRECT)
				{
					_mTblItem[key].rspflow += item.reqflow;	
				}
				else if(icmph->type == ICMP_TIMESTAMP)
				{
					_mTblItem[key].reqflow += item.reqflow;	
				}
				else if(icmph->type == ICMP_ADDRESS)
				{
					_mTblItem[key].reqflow += item.reqflow;	
				}

			}

			break;
		case ICMP_ECHOREPLY:
		case ICMP_TIMESTAMPREPLY:
		case ICMP_ADDRESSREPLY:
			if(icmph->type == ICMP_ECHOREPLY)
				icmp_type = ENUM_ICMP_ECHO;
			else if(icmph->type == ICMP_TIMESTAMPREPLY)
				icmp_type = ENUM_ICMP_TIMESTAMP;
			else if(icmph->type == ICMP_ADDRESS)
				icmp_type = ENUM_ICMP_ADDRESS;

			//key is dmac:smac:sip:dip:type
			key = lexical_cast<string>(item.smac)+":"+lexical_cast<string>(item.dmac)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(icmp_type);

			if(_mTblItem.find(key) != _mTblItem.end())
			{
				_mTblItem[key].rsppkts++;	
				_mTblItem[key].rspflow += item.reqflow;	
			}
			break;
		default:
			break;

	}
	sem_post(&_sem);////////////////////////////////

	return ret;
}
int CIcmpAudit::get_mTblItem_fintimeout(map<string,stTblItem> &dstm)
{
	int ret = 0;
	sem_wait(&_sem);
	dstm = _mTblItem;
	_mTblItem.clear();
	ret = dstm.size();
	sem_post(&_sem);
	return 	ret;
}
int CIcmpAudit::get_mTblItem_fin(multimap<string,stTblItem> &dstm)
{
	return 0;
}

CArpAudit::CArpAudit()
{
	sem_init(&_sem,0,1);
}
CArpAudit::~CArpAudit()
{
	sem_destroy(&_sem);
}
int CArpAudit::audit(const void *hdr, int hdrlen, stTblItem &item,int dir)
{
	assert(hdr != NULL);
	int ret = 0;
	struct arphdr *arph = NULL;
	struct arpdata *arpd = NULL;
	uint16_t hrd,pro,op;
	uint32_t isendip,itargetip;
	uint64_t lsendmac,ltargetmac;
	u_char hln,pln;
	string key;
	int arp_type;
	string strftype;

	arph = (struct arphdr*)hdr;
	hrd = ntohs(arph->ar_hrd);
	pro = ntohs(arph->ar_pro);
	op  = ntohs(arph->ar_op);
	hln = arph->ar_hln;
	pln = arph->ar_pln;

	//just support ipv4
	if(hrd!=ARPHRD_ETHER || hln!=0x06 || pln!=0x04)
		return -1;
	

	#if 1
	//#pragma
	arpd = (struct arpdata*)((char*)arph + sizeof(struct arphdr));

	//save arp mac to stTblItem port
	lsendmac   = mac_2_int(arpd->sendmac,sizeof(arpd->sendmac));
	isendip   = arpd->sendip;
	ltargetmac = mac_2_int(arpd->targetmac,sizeof(arpd->targetmac));
	itargetip = arpd->targetip;

	#if DEBUG
	cout<<"...... arp ...... sendmac:"<<lsendmac<<endl;
	_hex_dump(arpd->sendmac,6);
	cout<<"...... arp ...... sendip:"<<inaddr_2_ip(isendip)<<endl;
	cout<<"...... arp ...... targetmac:"<<ltargetmac<<endl;
	_hex_dump(arpd->targetmac,6);
	cout<<"...... arp ...... targetip:"<<inaddr_2_ip(itargetip)<<endl;
	#endif

	#else
	u_char *arpp;
	u_char mac[6];
	uint32_t *si;

	arpp = (u_char*)((char*)arph + sizeof(struct arphdr));
	memcpy(mac,arpp,6);
	cout<<"...... arp ...... sendmac:\n";
	_hex_dump(mac,6);
	arpp += 6;
	si = (uint32_t*)(arpp);
	cout<<"...... arp ...... sendip:"<<inaddr_2_ip(*si)<<endl;
	arpp += 4;
	memcpy(mac,arpp,6);
	cout<<"...... arp ...... targetmac:\n";
	_hex_dump(mac,6);
	arpp += 6;
	si = (uint32_t*)(arpp);
	cout<<"...... arp ...... targetip:"<<inaddr_2_ip(*si)<<endl;
	#endif

	sem_wait(&_sem);////////////////////////////////
	switch(op)
	{
		case ARPOP_REQUEST:
		case ARPOP_RREQUEST:
		case ARPOP_InREQUEST:
			if(op == ARPOP_REQUEST)
			{
				arp_type = ENUM_AUDIT_ARPTYPE_ARP;
				strftype = "ARP";
			}
			else if(op == ARPOP_RREQUEST)
			{
				arp_type = ENUM_AUDIT_ARPTYPE_RARP;
				strftype = "RARP";
			}
			else if(op == ARPOP_InREQUEST)
			{
				arp_type = ENUM_AUDIT_ARPTYPE_INARP;
				strftype = "InARP";
			}
			//key is dmac:smac:sendmac:sendip:targetip:type
			key = lexical_cast<string>(item.dmac)+":"+lexical_cast<string>(item.smac)+":" \
			      +lexical_cast<string>(lsendmac)+":"+lexical_cast<string>(isendip)+":"  \
			      +lexical_cast<string>(itargetip)+":" \
			      +lexical_cast<string>(arp_type);
			if(_mTblItem.find(key) == _mTblItem.end())
			{
				g_total_audit++;
				item.auditid = get_audit_id(g_total_audit);
				item.starttime = item.starttime;
				item.endtime = "";
				item.ethtype = ENUM_AUDIT_ETHTYPE_ARP;
				item.apptype = arp_type;
				item.ftypename = strftype;
				item.sip = isendip;
				item.dip = itargetip;
				//arp no port, this item as sendmac and target mac 
				item.sport = lsendmac;
				item.dport = ltargetmac;
				item.reqpkts = 1;
				item.rsppkts = 0;
				item.reqflow = item.reqflow;
				item.rspflow = 0;
				item.sessionstate = ENUM_ARP_REQ;
				_mTblItem[key] = item;	
			}
			else
			{
				_mTblItem[key].reqpkts++;	
				_mTblItem[key].reqflow += item.reqflow;	
			}

			break;
		case ARPOP_REPLY:
		case ARPOP_RREPLY:
		case ARPOP_InREPLY:
			if(op == ARPOP_REPLY)
				arp_type = ENUM_AUDIT_ARPTYPE_ARP;
			else if(op == ARPOP_RREPLY)
				arp_type = ENUM_AUDIT_ARPTYPE_RARP;
			else if(op == ARPOP_InREPLY)
				arp_type = ENUM_AUDIT_ARPTYPE_INARP;

			//key is smac:dmac:targetmac:targetip:sendip:type
			key = lexical_cast<string>(item.smac)+":"+lexical_cast<string>(item.dmac)+":" \
			      +lexical_cast<string>(ltargetmac)+":"+lexical_cast<string>(itargetip)+":"  \
			      +lexical_cast<string>(isendip)+":" \
			      +lexical_cast<string>(arp_type);
			if(_mTblItem.find(key) != _mTblItem.end())
			{
				_mTblItem[key].rsppkts++;	
				_mTblItem[key].rspflow += item.reqflow;	
			}
			break;
		default:
			return 0;
	}
	sem_post(&_sem);////////////////////////////////

	return ret;
}
int CArpAudit::get_mTblItem_fintimeout(map<string,stTblItem> &dstm)
{
	int ret = 0;
	sem_wait(&_sem);
	dstm = _mTblItem;
	_mTblItem.clear();
	ret = dstm.size();
	sem_post(&_sem);
	return 	ret;
}
int CArpAudit::get_mTblItem_fin(multimap<string,stTblItem> &dstm)
{
	return 0;
}



#if 0
int main()
{
	CTcpAudit * ctcp = new CTcpAudit;
	delete ctcp;
}

#endif
