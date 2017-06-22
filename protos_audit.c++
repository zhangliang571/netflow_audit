
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
#include "date_time.h"

using namespace boost;

CBaseAudit::CBaseAudit()
{

}
CBaseAudit::~CBaseAudit()
{

}


CTcpAudit::CTcpAudit()
{
	sem_init(&_sem,0,1);
}
CTcpAudit::~CTcpAudit()
{
	_mSession.clear();
	_mmSessionEnd.clear();
	_mSessionTimeout.clear();
	_vSessionTimeout.clear();
	sem_destroy(&_sem);
}
int CTcpAudit::audit(void *hdr, stTblItem &item)
{
	assert(hdr != NULL);
	struct tcphdr *tcph = NULL;
	uint16_t sport,dport;
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

		if(_mSessionTimeout.find(key) != _mSessionTimeout.end())
		{
			sem_wait(&_sem);////////////////////////////////
			_mSessionTimeout[key].endtime = item.starttime;
			_mSessionTimeout[key].sessionstate = ENUM_RST;
			_mSessionTimeout[key].rspflow += item.reqflow;
			_mmSessionEnd.insert(pair<string,stTblItem>(key,_mSessionTimeout[key]));

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
			sem_post(&_sem);////////////////////////////////
		}
		else if((itm=_mSession.find(key)) != _mSession.end())
		{
			itm->second.endtime = item.starttime;
			itm->second.sessionstate = ENUM_RST;
			itm->second.rspflow += item.reqflow;
			sem_wait(&_sem);////////////////////////////////
			_mmSessionEnd.insert(pair<string,stTblItem>(key,itm->second));
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

			vmng.strTime = item.starttime;
			vmng.strMapkey = key;
			_vSessionTimeout.push_back(vmng);
		}
		//new connect at half close
		else
		{
			//if(itm->second.sessionstate == ENUM_CLIENT_CLOSE_HALF || itm->second.sessionstate==ENUM_SERVER_CLOSE_HALF)
			{
				_totalTCP++;
				_mmSessionEnd.insert(pair<string,stTblItem>(key,itm->second));
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

				vmng.strTime = item.starttime;
				vmng.strMapkey = key;
				_vSessionTimeout.push_back(vmng);
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
		cout<<"end  tcp connect...............sip:"<<item.sip<<" dip:"<<item.dip<<"sport:"<<sport<<" dport:"<<dport<<endl;
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
				_mmSessionEnd.insert(pair<string,stTblItem>(key,itm->second));
				_mSession.erase(itm);
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
					_mmSessionEnd.insert(pair<string,stTblItem>(key,itm->second));
					_mSession.erase(itm);
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
int CIcmpAudit::get_mTblItem_fin(multimap<string,stTblItem> &dstm)
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
