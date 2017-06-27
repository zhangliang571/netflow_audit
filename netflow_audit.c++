#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
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
uint64_t g_total_audit;


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
	CTcpAudit *_cTcpAudit   = new CTcpAudit;
	CUdpAudit *_cUdpAudit   = new CUdpAudit;
	CIcmpAudit *_cIcmpAudit = new CIcmpAudit;
	CArpAudit *_cArpAudit   = new CArpAudit;
	_aCBaseAudit[ENUM_AUDIT_ETHTYPE_TCP]  = _cTcpAudit;
	_aCBaseAudit[ENUM_AUDIT_ETHTYPE_UDP]  = _cUdpAudit;
	_aCBaseAudit[ENUM_AUDIT_ETHTYPE_ICMP] = _cIcmpAudit;
	_aCBaseAudit[ENUM_AUDIT_ETHTYPE_ARP]  = _cArpAudit;
	return ENUM_AUDIT_ETHTYPE_TOT;
}
int CNetflowAudit::umount_baseaudit()
{
	for(int i=0;i<ENUM_AUDIT_ETHTYPE_TOT;i++)
		if(_aCBaseAudit[i] != NULL)
		delete _aCBaseAudit[i];
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

int CNetflowAudit::load_over_session_2_file(string strtmpfile)
{
	int ret = 0;
	ofstream of;
	multimap<string,stTblItem> mdata;

	for(int i=0;i<ENUM_AUDIT_ETHTYPE_TOT;i++)
	{
		int n = 0;
		mdata.clear();
		if(_aCBaseAudit[i] != NULL)
		n = _aCBaseAudit[i]->get_mTblItem_fin(mdata);
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

int CNetflowAudit::load_mTimeout_2_file(string strtmpfile)
{
	int ret = 0;
	ofstream of;
	map<string,stTblItem> mdata;

	for(int i=0;i<ENUM_AUDIT_ETHTYPE_TOT;i++)
	{
		int n = 0;
		mdata.clear();
		if(_aCBaseAudit[i] != NULL)
		n = _aCBaseAudit[i]->get_mTblItem_fintimeout(mdata);
		if(n > 0)
		{
			of.open(strtmpfile.c_str(), ios::app);	
			load_tblitem_2_ofstream(of, mdata);
			of.close();
			ret += n;
		}
	}
	return ret;
}

template <typename mapT>
int CNetflowAudit::load_tblitem_2_ofstream(ofstream& of,mapT &m)
{
	int ret = 0;
	typename mapT::iterator itm;
	if(of.is_open())
	{
		for(itm=m.begin();itm!=m.end();itm++)
		{
			ret++;
		      of<<"0"<<","
			<<"\""<<itm->second.auditid<<"\","
			<<"\""<<itm->second.starttime<<"\","
			<<"\""<<itm->second.endtime<<"\","
			<<"\""<<itm->second.ethtype<<"\","
			<<"\""<<itm->second.apptype<<"\","
			<<"\""<<itm->second.ftypename<<"\","
			<<"\""<<itm->second.dmac<<"\","
			<<"\""<<itm->second.smac<<"\","
			<<"\""<<inaddr_2_ip(itm->second.sip)<<"\","
			<<"\""<<inaddr_2_ip(itm->second.dip)<<"\","
			<<"\""<<itm->second.sport<<"\","
			<<"\""<<itm->second.dport<<"\","
			<<"\""<<itm->second.reqpkts<<"\","
			<<"\""<<itm->second.rsppkts<<"\","
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
	int ret = 0;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct icmphdr *icmph= NULL;
	CBaseAudit* pBaseAudit = NULL;
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
				pBaseAudit = _aCBaseAudit[ENUM_AUDIT_ETHTYPE_TCP];
				if(pBaseAudit)
				ret = pBaseAudit->audit(tcph, _tmpitem);

				break;
			case IPPROTO_UDP:
				udph = (struct udphdr*)((u_char*)iph + iph->ihl*4);
				pBaseAudit = _aCBaseAudit[ENUM_AUDIT_ETHTYPE_UDP];
				if(pBaseAudit)
				ret = pBaseAudit->audit(udph, _tmpitem);
				break;
			case IPPROTO_ICMP:
				icmph = (struct icmphdr*)((u_char*)iph + iph->ihl*4);
				pBaseAudit = _aCBaseAudit[ENUM_AUDIT_ETHTYPE_ICMP];
				if(pBaseAudit)
				ret = pBaseAudit->audit(icmph, _tmpitem);
				break;
			case IPPROTO_IGMP:
			case IPPROTO_GRE:
				break;


#if 0
			case IPPROTO_AH:
			case IPPROTO_ESP:
			case IPPROTO_IPCOMP:
			case IPPROTO_SCTP:

			case IPPROTO_DCCP:

			case IPPROTO_PIGP:
			case IPPROTO_EIGRP:

			case IPPROTO_ND:

			case IPPROTO_EGP:

			case IPPROTO_OSPF:
			case IPPROTO_IPV4:
#ifdef INET6
			case IPPROTO_IPV6:
#endif /*INET6*/

			case IPPROTO_RSVP:
			case IPPROTO_MOBILE:

			case IPPROTO_PIM:

			case IPPROTO_VRRP:
			case IPPROTO_PGM:

#endif
			default:
				break;
		}
		
	}
	return ret;
}

int CNetflowAudit::arp_layer_parse(const u_char* p, u_int length)
{
	int ret = 0;
	CBaseAudit* pBaseAudit = NULL;
	pBaseAudit = _aCBaseAudit[ENUM_AUDIT_ETHTYPE_ARP];
	if(pBaseAudit)
		ret = pBaseAudit->audit(p, _tmpitem);
	return ret;
}

int CNetflowAudit::ether_layer_parse(u_short ether_type, const u_char* p, u_int length)
{
	switch (ether_type) 
	{
		case ETHERTYPE_IP:
			ip_layer_parse(p,length);
			return (1);

		case ETHERTYPE_IPV6:
			break;
		case ETHERTYPE_ARP:
		case ETHERTYPE_REVARP:
			arp_layer_parse(p,length);
			return (1);

#if 0
		case ETHERTYPE_DN:
			return (1);

		case ETHERTYPE_ATALK:
			return (1);

		case ETHERTYPE_AARP:
			return (1);

		case ETHERTYPE_IPX:
			return (1);

		case ETHERTYPE_ISO:
			return(1);

		case ETHERTYPE_PPPOED:
		case ETHERTYPE_PPPOES:
		case ETHERTYPE_PPPOED2:
		case ETHERTYPE_PPPOES2:
			return (1);

		case ETHERTYPE_EAPOL:
			return (1);

		case ETHERTYPE_RRCP:
			return (1);

		case ETHERTYPE_PPP:
			return (1);

		case ETHERTYPE_MPCP:
			return (1);

		case ETHERTYPE_SLOW:
			return (1);

		case ETHERTYPE_CFM:
		case ETHERTYPE_CFM_OLD:
			return (1);

		case ETHERTYPE_LLDP:
			return (1);

		case ETHERTYPE_LOOPBACK:
			return (1);

		case ETHERTYPE_MPLS:
		case ETHERTYPE_MPLS_MULTI:
			return (1);

		case ETHERTYPE_TIPC:
			return (1);

		case ETHERTYPE_MS_NLB_HB:
			return (1);

		case ETHERTYPE_GEONET_OLD:
		case ETHERTYPE_GEONET:
			return (1);

		case ETHERTYPE_CALM_FAST:
			return (1);

		case ETHERTYPE_LAT:
		case ETHERTYPE_SCA:
		case ETHERTYPE_MOPRC:
		case ETHERTYPE_MOPDL:
#endif
		default:
			return (0);
	}
	return 0;
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
	const int SLEEP_TIME = 3;
	const int circleN = NO_CONNECT_TIMEOUT/SLEEP_TIME;
	int ret = 0;
	int n = 0;
	pthread_detach(pthread_self());
	CNetflowAudit *pNA = g_NetflowAudit;
	string strfile,strtmpfile;

	while(1)
	{
		get_save_file_name(SAVE_FILE,WDD_NETFLOW_AUDIT,strtmpfile,strfile);
		ret = pNA->load_over_session_2_file(strtmpfile);
		if(ret>0)	
		{
			#if DEBUG 
			//backup
			cout<<"load_over_session_2_file :"<<ret<<endl;
			string cmd = string("cp -f ") + strtmpfile + " /tmp/zl";
			system(cmd.c_str());
			#endif

			rename(strtmpfile.c_str(),strfile.c_str());
		}

		//every 180s check _mSession
		if(n++ > circleN)
		{
			n = 0;
			
			get_save_file_name(SAVE_FILE,WDD_NETFLOW_AUDIT,strtmpfile,strfile);
			ret = pNA->load_mTimeout_2_file(strtmpfile);
			if(ret>0)
			{
			#if DEBUG 
			//backup
			cout<<"load_mTimeout_2_file "<<strtmpfile<<" :"<<ret<<endl;;
			string cmd = string("cp -f ") + strtmpfile + " /tmp/zl";
			system(cmd.c_str());
			#endif

			rename(strtmpfile.c_str(),strfile.c_str());
			}
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

	#if DEBUG 
	system("mkdir -p /tmp/zl");
	#endif
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
