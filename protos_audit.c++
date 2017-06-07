
#include <iostream>
#include <string>
#include <vector>
#include <boost/lexical_cast.hpp>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <netinet/in.h>
#include <cassert>
#include <semaphore.h>
#include "protos_audit.h"
#include "proto_type.h"
#include "base.h"

using namespace boost;

CBaseAudit::CBaseAudit()
{

}
CBaseAudit::~CBaseAudit()
{

}


CTcpAudit::CTcpAudit()
{

}
CTcpAudit::~CTcpAudit()
{

}
int CTcpAudit::audit(void *hdr, stTblItem &item)
{
	assert(hdr != NULL);
	struct tcphdr *tcph = NULL;
	uint16_t sport,dport;
	map<string,stTblItem>::iterator itm ;
	string key;

	tcph = (struct tcphdr*)((u_char*)hdr);
	sport = ntohs(tcph->source);
	dport = ntohs(tcph->dest);

	//tcp connect rst
	if(tcph->rst == 1 && tcph->ack==1)
	{
		_dir = ENUM_RSP;
		key = lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport);
		if((itm=_mSession.find(key)) != _mSession.end())
		{
			itm->second.endtime = item.starttime;
			itm->second.sessionstate = ENUM_RST;
			itm->second.rspflow += item.reqflow;
			sem_wait(&_sem);////////////////////////////////
			_mSessionEnd[key] = itm->second;
			sem_post(&_sem);////////////////////////////////
			_mSession.erase(itm);
		}
	}	
	//req 3 handles
	else if(tcph->syn == 1 && tcph->ack==0 && tcph->ece==0&&tcph->cwr==0)
	{
		_dir = ENUM_REQ;
		key = lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport);
		sem_wait(&_sem);////////////////////////////////
		if((itm=_mSessionTimeout.find(key)) == _mSessionTimeout.end())
		{
			_totalTCP++;
			item.auditid = get_audit_id(_totalTCP);
			item.starttime = item.starttime;
			item.endtime = "";
			item.ftype = "TCP";
			item.sport = sport;
			item.dport = dport;
			item.reqflow = item.reqflow;
			item.rspflow = 0;
			item.sessionstate = ENUM_CONNECT_REQ;

			_mSessionTimeout[key] =  item;
		}
		//new connect at half close
		else
		{
			//if(itm->second.sessionstate == ENUM_CLIENT_CLOSE_HALF || itm->second.sessionstate==ENUM_SERVER_CLOSE_HALF)
			{
				_totalTCP++;
				_mSessionEnd[key] = itm->second;
				_mSessionTimeout.erase(key);

				item.auditid = get_audit_id(_totalTCP);
				item.starttime = item.starttime;
				item.endtime = "";
				item.ftype = "TCP";
				item.sport = sport;
				item.dport = dport;
				item.reqflow = item.reqflow;
				item.rspflow = 0;
				item.sessionstate = ENUM_CONNECT_REQ;

				_mSessionTimeout[key] =  item;
			}

		}
		sem_post(&_sem);////////////////////////////////
	}
	//rsp 3 handles
	else if(tcph->syn == 1 && tcph->ack==1)
	{
		_dir = ENUM_RSP;
		cout<<"rsp 3 handles ..............sip:"<<item.dip<<" sport:"<<dport<<" dip:"<<item.sip<<" dport:"<<sport<<endl;
		key = lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport);
		sem_wait(&_sem);////////////////////////////////
		if((itm=_mSessionTimeout.find(key)) != _mSessionTimeout.end())
		{
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
		//cout<<"end   tcp connect...............sip:"<<item.sip<<" dip:"<<item.dip<<"sport:"<<sport<<" dport:"<<dport<<endl;
		key = lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport);
		sem_wait(&_sem);////////////////////////////////
		if((itm=_mSession.find(key)) != _mSession.end())
		{
			_dir = ENUM_REQ;
			if(itm->second.sessionstate == ENUM_SERVER_CLOSE_HALF)
			{
				itm->second.endtime = item.starttime;
				itm->second.reqflow += item.reqflow;
				itm->second.sessionstate  = ENUM_CLOSE_SUCCESS;		
				_mSessionEnd[key] = itm->second;
				_mSession.erase(itm);
				_mSessionTimeout.erase(key);
			}
			else
			{
				itm->second.endtime = item.starttime;
				itm->second.reqflow += item.reqflow;
				itm->second.sessionstate  = ENUM_CLIENT_CLOSE_HALF;		
				_mSessionTimeout[key] = itm->second;
				_mSession.erase(itm);
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
					itm->second.rspflow += item.reqflow;
					itm->second.sessionstate  = ENUM_CLOSE_SUCCESS;		
					_mSessionEnd[key] = itm->second;
					_mSession.erase(itm);
					_mSessionTimeout.erase(key);
				}
				else
				{
					itm->second.endtime = item.starttime;
					itm->second.rspflow += item.reqflow;
					itm->second.sessionstate  = ENUM_SERVER_CLOSE_HALF;		
					_mSessionTimeout[key] = itm->second;
					_mSession.erase(itm);
				}
			}

		}
		sem_post(&_sem);////////////////////////////////
	}
	else
	{
		key = lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport);
		if(_mSession.find(key) != _mSession.end())
		{
			_dir = ENUM_REQ;
			_mSession[key].reqflow += item.reqflow;
		}
		else
		{
			key = lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport);
			if(_mSession.find(key) != _mSession.end())
			{
				_dir = ENUM_RSP;
				_mSession[key].rspflow += item.reqflow;
			}
		}
	}


}
int CTcpAudit::get_mTblItem_fintimeout(map<string,stTblItem> &dstm)
{
	int ret = 0;
	map<string,stTblItem>::iterator itm;
	sem_wait(&_sem);
	dstm = _mSessionEnd;
	_mSessionEnd.clear();
	for(itm=_mSessionTimeout.begin();itm!=_mSessionTimeout.end();itm++)
	{
		//_mSessionTimeout have not the same key with _mSessionEnd
		dstm[itm->first] = itm->second;
	}

	ret = dstm.size();
	sem_post(&_sem);
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
int CUdpAudit::audit(void *hdr, stTblItem &item)
{
	assert(hdr != NULL);
	struct udphdr *udph = NULL;
	uint16_t sport,dport;
	string key;

	udph = (struct udphdr*)((u_char*)hdr);


	sport = ntohs(udph->source);
	dport = ntohs(udph->dest);

	key = lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport);

	cout<<"CUdpAudit::audit() ...... "<<key<<endl;

	sem_wait(&_sem);////////////////////////////////
	if(_mTblItem.find(key) == _mTblItem.end())
	{
		string keyrsp = lexical_cast<string>(item.dip)+":"+lexical_cast<string>(dport)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(sport);
		if(_mTblItem.find(keyrsp) == _mTblItem.end())
		{
			_dir = ENUM_REQ;	
			_totalUDP++;
			item.auditid = get_audit_id(_totalUDP);
			item.starttime = item.starttime;
			item.endtime = "";
			item.ftype = "UDP";
			item.sport = sport;
			item.dport = dport;
			item.reqflow = item.reqflow;
			item.rspflow = 0;
			item.sessionstate = ENUM_UDP;
			_mTblItem[key] = item;	

		}
		else
		{
			_dir = ENUM_RSP;	
			_mTblItem[keyrsp].rspflow += item.reqflow;
		}

	}
	else
	{
		_dir = ENUM_REQ;	
		_mTblItem[key].rspflow += item.reqflow;
	}
	sem_post(&_sem);////////////////////////////////

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

CIcmpAudit::CIcmpAudit()
{
	sem_init(&_sem,0,1);
}
CIcmpAudit::~CIcmpAudit()
{
	sem_destroy(&_sem);
}
int CIcmpAudit::audit(void *hdr, stTblItem &item)
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
			icmp_type = ENUM_ICMP_ECHO;
		case ICMP_DEST_UNREACH:
			icmp_type = ENUM_ICMP_DEST_UNREACH;
		case ICMP_REDIRECT:
			icmp_type = ENUM_ICMP_REDIRECT;
		case ICMP_TIMESTAMP:
			icmp_type = ENUM_ICMP_TIMESTAMP;
		case ICMP_ADDRESS:
			icmp_type = ENUM_ICMP_ADDRESS;

			//key is dmac:smac:sip:dip:type
			key = lexical_cast<string>(item.dmac)+":"+lexical_cast<string>(item.smac)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(icmp_type);

			cout<<"CIcmpAudit::audit() icmp............key:"<<key<<endl;
			if(_mTblItem.find(key) == _mTblItem.end())
			{
				_totalICMP++;
				item.auditid = get_audit_id(_totalICMP);
				item.starttime = item.starttime;
				item.endtime = "";
				item.ftype = "ICMP";
				//icmp no port, this item as icmp pkt count
				item.sport = 1;
				item.dport = 0;
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
				_mTblItem[key].sport += 1;	
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
			icmp_type = ENUM_ICMP_ECHO;
		case ICMP_TIMESTAMPREPLY:
			icmp_type = ENUM_ICMP_TIMESTAMP;
		case ICMP_ADDRESSREPLY:
			icmp_type = ENUM_ICMP_ADDRESS;

			//key is dmac:smac:sip:dip:type
			key = lexical_cast<string>(item.smac)+":"+lexical_cast<string>(item.dmac)+":"+lexical_cast<string>(item.dip)+":"+lexical_cast<string>(item.sip)+":"+lexical_cast<string>(icmp_type);

			cout<<"CIcmpAudit::audit() rsp icmp............key:"<<key<<endl;
			if(_mTblItem.find(key) != _mTblItem.end())
			{
				_mTblItem[key].dport += 1;	
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

#if 0
int main()
{
	CTcpAudit * ctcp = new CTcpAudit;
	delete ctcp;
}

#endif
