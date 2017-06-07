#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <pthread.h>
#include <cstdlib>

#include "netflow_audit.h"
#include "date_time.h"
#include "proto_type.h"

#define HAVE_PF_RING
#include <pfring.h>


using namespace std;

CDateTime *g_Date; 
CNetflowAudit *g_NetflowAudit; 


int g_coll_count;
void coll_pcap_handle(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* pkt)
{
	assert(pkthdr!=NULL);
	struct framehdr *fm = NULL;
	uint16_t *ptype = NULL;
	uint16_t ethtype = 0;
	uint64_t ul = 0;
	int vlanlen = 0;
	u_int length = 0;
	u_char *p = NULL;
	CNetflowAudit *pNA = g_NetflowAudit;

	length = pkthdr->caplen;
	if(length < ETHER_HDRLEN)
		return;
	
	g_coll_count++;

	fm = (struct framehdr*)pkt;
	
	ethtype = ntohs(fm->ftype);
	if(  ethtype == ETHERTYPE_8021Q
	   ||ethtype == ETHERTYPE_8021Q9100
	   ||ethtype == ETHERTYPE_8021Q9200
	   ||ethtype == ETHERTYPE_8021QinQ )
	{
		ptype = (uint16_t*)((u_char*)pkt + sizeof(struct framehdr)+ ETHERTYPE_LEN);
		ethtype = ntohs(*ptype);
		vlanlen = 4;
	}

	p = (u_char*)((u_char*)pkt + sizeof(struct framehdr) + vlanlen);
	length = length - sizeof(struct framehdr) - vlanlen;

	pNA->_zero_stTblItem();

	pNA->_tmpitem.starttime = g_Date->timestamp_2_string(pkthdr->ts.tv_sec);
	pNA->_tmpitem.smac = mac_2_int(fm->srcmac,sizeof(fm->srcmac));
	pNA->_tmpitem.dmac = mac_2_int(fm->dstmac,sizeof(fm->dstmac));
	pNA->_tmpitem.reqflow = pkthdr->caplen;

	pNA->ether_layer_parse(ethtype, p, length);

	#if 0
	cout<<"time:"<<g_Date->timestamp_2_string(pkthdr->ts.tv_sec)<<endl;
	cout<<"caplen:"<<pkthdr->caplen<<endl;
	cout<<"len:"<<pkthdr->len<<endl;
	cout<<"srcmac:";
	_hex_dump(fm->srcmac,6);
	cout<<"dstmac:";
	_hex_dump(fm->dstmac,6);
	cout<<"ftype:0x"<<hex<<ethtype<<dec<<endl;
	cout<<"length:"<<length<<endl;
	#endif


}


CNetflowAudit::CNetflowAudit()
{
	_strdev = "eth0";
	init();
}
CNetflowAudit::CNetflowAudit(const char *dev)
{
	_strdev = dev;
	init();
}
CNetflowAudit::~CNetflowAudit()
{
	umount_baseaudit();
	close_pcap(_pd);
	_pd = NULL;
}
int CNetflowAudit::init()
{
	mount_baseaudit();
	_pd = open_pcap(_strdev.c_str());
	if(!_pd)
		throw("CNetflowAudit::init err");
	return 0;
}
int CNetflowAudit::mount_baseaudit()
{
	CTcpAudit *_cTcpAudit  = new CTcpAudit;
	CUdpAudit *_cUdpAudit  = new CUdpAudit;
	CIcmpAudit *_cIcmpAudit  = new CIcmpAudit;
	_vCBaseAudit.push_back(_cTcpAudit);
	_vCBaseAudit.push_back(_cUdpAudit);
	_vCBaseAudit.push_back(_cIcmpAudit);
	return _vCBaseAudit.size();
}
int CNetflowAudit::umount_baseaudit()
{
	vector<CBaseAudit*>::iterator itv;
	for(itv=_vCBaseAudit.begin();itv!=_vCBaseAudit.end();itv++)
		delete *itv;
}
void CNetflowAudit::_zero_stTblItem()
{
	zero_stTblItem(_tmpitem);
}


void CNetflowAudit::Run()
{
	int ret = 0;
	int n = 0;
	while(1)
	{
		ret = pcap_dispatch(_pd,-1,(pcap_handler)(&coll_pcap_handle),NULL);	
		if(ret<0)
		{
			cout<<"pcap_dispatch() err!!!\n";
			break;
		}
		else if(ret == 0)
		{
			usleep(10);//cout<<"pcap_dispatch() no catch packges......\n";
		}
		else
		{
			n+=ret;
			//cout<<"\nret:"<<ret<<"n"<<n<<endl;
			//if(n>100)
			//break;
		}
	}

}


pcap_t* CNetflowAudit::open_pcap(const char *dev)
{
	int snaplen = 4096;
	int PCAP_TIMEOUT = 1000;
	char errbuf[256];
	pcap_t *pd = NULL;
	struct bpf_program pcapfilter;
	uint32_t mask = 0xffff0000;
	uint32_t net = 0;
	const char *filter = NULL;

	assert(dev!=NULL);

	if(pcap_lookupnet(dev,&net,&mask,errbuf) <0)
	{
		net = 0;
		mask = 0xffffff00;
		cout<<"pcap_lookupnet() err:"<<errbuf<<endl;
	}
	cout<<"find dev:"<<dev<<" mask:0x"<<hex<<mask<<" net:0x"<<net<<" ip:"<<inaddr_2_ip(net)<<dec<<endl;

	pd = pcap_open_live(dev,snaplen,1,PCAP_TIMEOUT,errbuf);
	if(!pd)
	{
		cout<<"pcap_open_live() err:"<<errbuf<<endl;
		return NULL;
	}
	pcap_compile(pd,&pcapfilter, filter, 1, mask);
	pcap_setfilter(pd,&pcapfilter);
	//set nonblock mode
	pcap_setnonblock(pd,1,errbuf);

	return pd;	
}

void CNetflowAudit::close_pcap(pcap_t *pd)
{
	if(pd)
	{
		pcap_close(pd);
	}
}

int CNetflowAudit::load_mTimeout_2_file(string strtmpfile)
{
	int ret = 0;
	ofstream of;
	map<string,stTblItem> mdata;
	vector<CBaseAudit*>::iterator itv;

	for(itv=_vCBaseAudit.begin();itv!=_vCBaseAudit.end();itv++)
	{
		int n = 0;
		n = (*itv)->get_mTblItem_fintimeout(mdata);
		if(n >0)
		{
			of.open(strtmpfile.c_str(), ios::app);	
			load_tblitem_2_ofstream(of, mdata);
			of.close();
			ret += n;
		}
	}
	return ret;
}

int CNetflowAudit::load_tblitem_2_ofstream(ofstream& of,map<string,stTblItem> &m)
{
	int ret = 0;
	map<string,stTblItem>::iterator itm;
	if(of.is_open())
	{
		for(itm=m.begin();itm!=m.end();itm++)
		{
			ret++;
		      of<<"0"<<","
			<<"\""<<itm->second.auditid<<"\","
			<<"\""<<itm->second.starttime<<"\","
			<<"\""<<itm->second.endtime<<"\","
			<<"\""<<itm->second.ftype<<"\","
			<<"\""<<itm->second.dmac<<"\","
			<<"\""<<itm->second.smac<<"\","
			<<"\""<<inaddr_2_ip(itm->second.sip)<<"\","
			<<"\""<<inaddr_2_ip(itm->second.dip)<<"\","
			<<"\""<<itm->second.sport<<"\","
			<<"\""<<itm->second.dport<<"\","
			<<"\""<<itm->second.reqflow<<"\","
			<<"\""<<itm->second.rspflow<<"\","
			<<"\""<<itm->second.sessionstate<<"\","
			<<"NULL"<<","
			<<"NULL"
			<<endl;
		}

	}
	return ret;	
}
void CNetflowAudit::echo_msession()
{
#if 0
	map<string,stTblItem>::iterator itm;
	for(itm=_mSession.begin();itm!=_mSession.end();itm++)
	{
		cout<<"###### session audit ######\n"
		<<"\tstarttime:"<<itm->second.starttime<<endl
		<<"\tendtime  :"<<itm->second.endtime<<endl
		<<"\tftype:"<<itm->second.ftype<<endl
		<<"\tdmac:"<<itm->second.dmac<<endl
		<<"\tsmac:"<<itm->second.smac<<endl
		<<"\tsip:"<<itm->second.sip<<endl
		<<"\tsport:"<<itm->second.sport<<endl
		<<"\tdip:"<<itm->second.dip<<endl
		<<"\tdport:"<<itm->second.dport<<endl
		<<"\treqflow:"<<itm->second.reqflow<<endl
		<<"\trspflow:"<<itm->second.rspflow<<endl
		<<"\tsessionstate:"<<g_session_state[itm->second.sessionstate-1]
		<<endl;
	}
	cout<<"_mSession.size():"<<_mSession.size()<<endl;
#endif
}

int CNetflowAudit::ip_layer_parse(const u_char* p, u_int length)
{
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct icmphdr *icmph= NULL;
	uint32_t isip,idip;
	uint16_t sport,dport;
	uint8_t icmp_type;
	string key;
	stTblItem item;
	map<string,stTblItem>::iterator itm;

	iph = (struct iphdr*)p;
	if(ntohs(iph->tot_len) > length)
		return -1;

	//now just support ipv4
	if(iph->version == IPPROTO_IPV4) 
	{
		isip = iph->saddr;
		idip = iph->daddr;
		_tmpitem.sip = (iph->saddr);	
		_tmpitem.dip = (iph->daddr);	
	
		switch(iph->protocol)
		{
			case IPPROTO_TCP:
				tcph = (struct tcphdr*)((u_char*)iph + iph->ihl*4);
				_vCBaseAudit[0]->audit(tcph, _tmpitem);

				break;
			case IPPROTO_UDP:
				udph = (struct udphdr*)((u_char*)iph + iph->ihl*4);
				_vCBaseAudit[1]->audit(udph, _tmpitem);
				break;
			case IPPROTO_ICMP:
				icmph = (struct icmphdr*)((u_char*)iph + iph->ihl*4);
				_vCBaseAudit[2]->audit(icmph, _tmpitem);
				break;
			case IPPROTO_IGMP:
			case IPPROTO_GRE:
				break;


#if 0
			case IPPROTO_AH:
				ipds->nh = *ipds->cp;
				ipds->advance = ah_print(ipds->cp);
				if (ipds->advance <= 0)
					break;
				ipds->cp += ipds->advance;
				ipds->len -= ipds->advance;
				goto again;

			case IPPROTO_ESP:
				{
					int enh, padlen;
					ipds->advance = esp_print(ndo, ipds->cp, ipds->len,
							(const u_char *)ipds->ip,
							&enh, &padlen);
					if (ipds->advance <= 0)
						break;
					ipds->cp += ipds->advance;
					ipds->len -= ipds->advance + padlen;
					ipds->nh = enh & 0xff;
					goto again;
				}

			case IPPROTO_IPCOMP:
				{
					int enh;
					ipds->advance = ipcomp_print(ipds->cp, &enh);
					if (ipds->advance <= 0)
						break;
					ipds->cp += ipds->advance;
					ipds->len -= ipds->advance;
					ipds->nh = enh & 0xff;
					goto again;
				}

			case IPPROTO_SCTP:
				sctp_print(ipds->cp, (const u_char *)ipds->ip, ipds->len);
				break;

			case IPPROTO_DCCP:
				dccp_print(ipds->cp, (const u_char *)ipds->ip, ipds->len);
				break;

			case IPPROTO_PIGP:
				/*
				 * XXX - the current IANA protocol number assignments
				 * page lists 9 as "any private interior gateway
				 * (used by Cisco for their IGRP)" and 88 as
				 * "EIGRP" from Cisco.
				 *
				 * Recent BSD <netinet/in.h> headers define
				 * IP_PROTO_PIGP as 9 and IP_PROTO_IGRP as 88.
				 * We define IP_PROTO_PIGP as 9 and
				 * IP_PROTO_EIGRP as 88; those names better
				 * match was the current protocol number
				 * assignments say.
				 */
				igrp_print(ipds->cp, ipds->len, (const u_char *)ipds->ip);
				break;

			case IPPROTO_EIGRP:
				eigrp_print(ipds->cp, ipds->len);
				break;

			case IPPROTO_ND:
				ND_PRINT((ndo, " nd %d", ipds->len));
				break;

			case IPPROTO_EGP:
				egp_print(ipds->cp, ipds->len);
				break;

			case IPPROTO_OSPF:
				ospf_print(ipds->cp, ipds->len, (const u_char *)ipds->ip);
				break;
			case IPPROTO_IPV4:
				/* DVMRP multicast tunnel (ip-in-ip encapsulation) */
				ip_print(ndo, ipds->cp, ipds->len);
				if (! vflag) {
					ND_PRINT((ndo, " (ipip-proto-4)"));
					return;
				}
				break;

#ifdef INET6
			case IPPROTO_IPV6:
				/* ip6-in-ip encapsulation */
				ip6_print(ndo, ipds->cp, ipds->len);
				break;
#endif /*INET6*/

			case IPPROTO_RSVP:
				rsvp_print(ipds->cp, ipds->len);
				break;
			case IPPROTO_MOBILE:
				mobile_print(ipds->cp, ipds->len);
				break;

			case IPPROTO_PIM:
				vec[0].ptr = ipds->cp;
				vec[0].len = ipds->len;
				pim_print(ipds->cp, ipds->len, in_cksum(vec, 1));
				break;

			case IPPROTO_VRRP:
				if (packettype == PT_CARP) {
					if (vflag)
						(void)printf("carp %s > %s: ",
								ipaddr_string(&ipds->ip->ip_src),
								ipaddr_string(&ipds->ip->ip_dst));
					carp_print(ipds->cp, ipds->len, ipds->ip->ip_ttl);
				} else {
					if (vflag)
						(void)printf("vrrp %s > %s: ",
								ipaddr_string(&ipds->ip->ip_src),
								ipaddr_string(&ipds->ip->ip_dst));
					vrrp_print(ipds->cp, ipds->len, ipds->ip->ip_ttl);
				}
				break;

			case IPPROTO_PGM:
				pgm_print(ipds->cp, ipds->len, (const u_char *)ipds->ip);
				break;

#endif
			default:
				break;
		}
		
	}
}

int CNetflowAudit::ether_layer_parse(u_short ether_type, const u_char* p, u_int length)
{
	switch (ether_type) 
	{
		case ETHERTYPE_IP:
			ip_layer_parse(p,length);
			return (1);

		case ETHERTYPE_IPV6:
		case ETHERTYPE_ARP:
		case ETHERTYPE_REVARP:
			return (1);

#if 0
		case ETHERTYPE_DN:
			decnet_print(/*ndo,*/p, length, caplen);
			return (1);

		case ETHERTYPE_ATALK:
			if (ndo->ndo_vflag)
				fputs("et1 ", stdout);
			atalk_print(/*ndo,*/p, length);
			return (1);

		case ETHERTYPE_AARP:
			aarp_print(/*ndo,*/p, length);
			return (1);

		case ETHERTYPE_IPX:
			ND_PRINT((ndo, "(NOV-ETHII) "));
			ipx_print(/*ndo,*/p, length);
			return (1);

		case ETHERTYPE_ISO:
			isoclns_print(/*ndo,*/p+1, length-1, length-1);
			return(1);

		case ETHERTYPE_PPPOED:
		case ETHERTYPE_PPPOES:
		case ETHERTYPE_PPPOED2:
		case ETHERTYPE_PPPOES2:
			pppoe_print(/*ndo,*/p, length);
			return (1);

		case ETHERTYPE_EAPOL:
			eap_print(ndo, p, length);
			return (1);

		case ETHERTYPE_RRCP:
			rrcp_print(ndo, p - 14 , length + 14);
			return (1);

		case ETHERTYPE_PPP:
			if (length) {
				printf(": ");
				ppp_print(/*ndo,*/p, length);
			}
			return (1);

		case ETHERTYPE_MPCP:
			mpcp_print(/*ndo,*/p, length);
			return (1);

		case ETHERTYPE_SLOW:
			slow_print(/*ndo,*/p, length);
			return (1);

		case ETHERTYPE_CFM:
		case ETHERTYPE_CFM_OLD:
			cfm_print(/*ndo,*/p, length);
			return (1);

		case ETHERTYPE_LLDP:
			lldp_print(/*ndo,*/p, length);
			return (1);

		case ETHERTYPE_LOOPBACK:
			return (1);

		case ETHERTYPE_MPLS:
		case ETHERTYPE_MPLS_MULTI:
			mpls_print(/*ndo,*/p, length);
			return (1);

		case ETHERTYPE_TIPC:
			tipc_print(ndo, p, length, caplen);
			return (1);

		case ETHERTYPE_MS_NLB_HB:
			msnlb_print(ndo, p);
			return (1);

		case ETHERTYPE_GEONET_OLD:
		case ETHERTYPE_GEONET:
			geonet_print(ndo, p-14, p, length);
			return (1);

		case ETHERTYPE_CALM_FAST:
			calm_fast_print(ndo, p-14, p, length);
			return (1);

		case ETHERTYPE_LAT:
		case ETHERTYPE_SCA:
		case ETHERTYPE_MOPRC:
		case ETHERTYPE_MOPDL:
			/* default_print for now */
#endif
		default:
			return (0);
	}
}


void user_signal(int iSigNum)
{
	cout<<"recv signal:"<<iSigNum<<endl;
	g_NetflowAudit->echo_msession();
	cout<<"g_coll_count:"<<g_coll_count<<endl;
}

//every 5sec save once
void* save2db_handle(void* arg)
{
	const int SLEEP_TIME = 5;
	const int circleN = 180/SLEEP_TIME;
	int ret = 0;
	int n = 0;
	pthread_detach(pthread_self());
	CNetflowAudit *pNA = g_NetflowAudit;
	string strfile,strtmpfile;

	while(1)
	{
		get_save_file_name(SAVE_FILE,WDD_NETFLOW_AUDIT,strtmpfile,strfile);
		ret = pNA->load_mTimeout_2_file(strtmpfile);
		if(ret>0)	
		{
#if 0
			//backup
			string cmd = string("cp -f ") + strtmpfile + " /tmp/zl";
			system(cmd.c_str());
#endif

			//move tmpfile to /data/input/
			rename(strtmpfile.c_str(),strfile.c_str());
		}

		//every 180s check _mSession
		if(n++ > circleN)
		{
			n = 0;
			
			get_save_file_name(SAVE_FILE,WDD_NETFLOW_AUDIT,strtmpfile,strfile);
			ret = pNA->load_mTimeout_2_file(strtmpfile);
				rename(strtmpfile.c_str(),strfile.c_str());
		}

		sleep(SLEEP_TIME);
	}
}
//load file into mysql
void* db_import_handle(void* arg)
{
	vector<string> vsqlfile;
	const char *pfilter = "wdd";
	const char *suffix = NULL;
	pthread_detach(pthread_self());

	while(1)
	{
		vsqlfile.clear();
		if(ls_dir(SAVE_FILE, pfilter, suffix, vsqlfile) > 0)
		{
			string bicmd = "mysqlimport  --local  --fields-enclosed-by=\\\" --fields-terminated-by=, -uroot lzhang -pa ";
			string rmcmd = "rm -f ";
			string strfiles = "";
			int i = 0;

			for(i=0;i<vsqlfile.size();i++)
			{
				strfiles += " "+vsqlfile[i];
				//mysqlimport 100 files once
				if((i+1)%100 == 0)	
				{
					bicmd += strfiles;
					system(bicmd.c_str());
					rmcmd += strfiles;
					system(rmcmd.c_str());
					strfiles = "";
				}
			}
			if(strfiles.size()>0)
			{
				bicmd += strfiles;
				system(bicmd.c_str());
				rmcmd += strfiles;
				system(rmcmd.c_str());
				strfiles = "";
			}

		}


		sleep(1);
	}
}
int main(int argc, char *argv[])
{
	const char *pdev = "ens33";
	pcap_t *pd = NULL;
	pid_t pid = getpid();
	pthread_t pid_dbimport,pid_save2db;
	int ret = 0;

	::signal(SIGUSR1,user_signal);
	pthread_create(&pid_dbimport,NULL,db_import_handle,NULL);

	try
	{
		g_Date = new CDateTime;
		cout<<g_Date->current_time()<<" hello NetFlow Audit\n";

		g_NetflowAudit = new CNetflowAudit(pdev);
		pthread_create(&pid_save2db ,NULL,save2db_handle,NULL);
		g_NetflowAudit->Run();
	}
	catch(const char *E)
	{
		cout<<g_Date->current_time()<<" catch err......"<<E<<endl;
	}



	
	delete g_Date;
	delete g_NetflowAudit;

	user_signal(10);
}
