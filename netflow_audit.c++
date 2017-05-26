#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <pthread.h>
#include <cstdlib>

#include "netflow_audit.h"
#include "date_time.h"
#include "ethertype.h"
#include "base.h"

#define HAVE_PF_RING
#include <pfring.h>


using namespace std;

CDateTime *g_Date; 
//key is sport, value is dport
map<int,int> g_mPorts[2];

pcap_t* open_pcap(const char *dev)
{
	int snaplen = 4096;
	int PCAP_TIMEOUT = 1000;
	char errbuf[256];
	pcap_t *pd = NULL;
	uint32_t mask = 0xffff0000;
	uint32_t net = 0;

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
		cout<<"pcap_open_live() err:"<<errbuf<<endl;
	
	//set nonblock mode
	pcap_setnonblock(pd,1,errbuf);

	return pd;	
}

void close_pcap(pcap_t *pd)
{
	if(pd)
		pcap_close(pd);
}

int ip_layer_parse(u_short ether_type, const u_char* p, u_int length)
{
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	uint16_t sport,dport;

	iph = (struct iphdr*)p;

	if(iph->version == 0x4) 
	{
		switch(iph->protocol)
		{
			//TCP
			case 0x6:
				tcph = (struct tcphdr*)(iph + iph->ihl*4);
				sport = ntohs(tcph->source);
				dport = ntohs(tcph->dest);
				if(g_mPorts[0].find(sport) == g_mPorts[0].end())
					g_mPorts[0][sport] = dport;
				break;
				//UDP
			case 0x11:
				udph = (struct udphdr*)(iph + iph->ihl*4);
				sport = ntohs(udph->source);
				dport = ntohs(udph->dest);
				if(g_mPorts[1].find(sport) == g_mPorts[1].end())
					g_mPorts[1][sport] = dport;
				break;
			default:
				return 0;
		}

	}
}

int ether_layer_parse(u_short ether_type, const u_char* p, u_int length)
{
	switch (ether_type) 
	{
		case ETHERTYPE_IP:
			ip_layer_parse(ether_type,p,length);
			return (1);

#if 0
		case ETHERTYPE_IPV6:
			ip6_print(ndo, p, length);
			return (1);
		case ETHERTYPE_ARP:
		case ETHERTYPE_REVARP:
			arp_print(ndo, p, length, caplen);
			return (1);

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

void coll_pcap_handle(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* pkt)
{
	assert(pkthdr!=NULL);
	struct framehdr *fm = NULL;
	uint16_t *ptype = NULL;
	uint16_t ethtype = 0;
	int vlanlen = 0;
	u_int length = 0;
	u_char *p = NULL;

	#if 0
	cout<<"timeval:"<<pkthdr->ts.tv_sec<<"."<<pkthdr->ts.tv_usec<<endl;
	cout<<"time:"<<g_Date->timestamp_2_string(pkthdr->ts.tv_sec)<<endl;
	cout<<"caplen:"<<pkthdr->caplen<<endl;
	cout<<"len:"<<pkthdr->len<<endl;
	cout<<"srcmac:"<<endl;
	_hex_dump(fm->srcmac,6);
	cout<<"dstmac:"<<endl;
	_hex_dump(fm->dstmac,6);
	#endif

	length = pkthdr->caplen;
	if(length < ETHER_HDRLEN)
		return;

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
	p = (u_char*)((u_char*)pkt + sizeof(struct framehdr)+ vlanlen);
	length -= vlanlen;
	ether_layer_parse(ethtype, p, length);

}

void user_signal(int iSigNum)
{
	cout<<"recv signal:"<<iSigNum<<endl;
	map<int,int>::iterator itm;
	for(int i=0;i<2;i++)
	{
	string s;
	if(i==0)
	s = "TCP stream:\n";
	else
	s = "UDP stream:\n";
	cout<<s;
	for(itm=g_mPorts[i].begin();itm!=g_mPorts[i].end();itm++)
		cout<<"\tsport:"<<itm->first<<"\tdport:"<<itm->second<<endl;
	}
}
void* db_import_handle(void* arg)
{
	vector<string> vsqlfile;
	pthread_detach(pthread_self());
	while(1)
	{
		if(ls_dir(SAVE_FILE,"wdd",".txt",vsqlfile) > 0)
		{
			string bicmd = "mysqlimport  --local  --fields-enclosed-by=\\\" --fields-terminated-by=, -uroot -pa lzhang ";
			string rmcmd = "rm -f ";
			string strfiles;

			for(int i=0;i<vsqlfile.size();i++)
			{
				strfiles += " "+vsqlfile[i];
				if(i/100 >= 0)	
				{
				bicmd += strfiles;
				system(bicmd.c_str());
				rmcmd += strfiles;
				system(rmcmd.c_str());
				strfiles = "";
				}
			}
			if(strfiles.size() > 0)
			{
				bicmd += strfiles;
				system(bicmd.c_str());
				rmcmd += strfiles;
				system(rmcmd.c_str());
			}
		}


		sleep(1);
	}
}
int main(int argc, char *argv[])
{
	pcap_t *pd = NULL;
	int ret = 0;
	cout<<g_Date->current_time()<<" hello NetFlow Audit\n";
	pd = open_pcap("ens33");


	::signal(SIGUSR1,user_signal);
	pthread_t pid;
	pthread_create(&pid,NULL,db_import_handle,NULL);

	g_Date = new CDateTime;
	int n = 0;
	while(1)
	{
		ret = pcap_dispatch(pd,-1,(pcap_handler)(coll_pcap_handle),NULL);	
		if(ret<0)
		{
			cout<<"pcap_dispatch() err!!!\n";
			break;
		}
		else if(ret == 0)
		{
			;//cout<<"pcap_dispatch() no catch packges......\n";
		}
		else
		{
			n+=ret;
			//cout<<"\nret:"<<ret<<"n"<<n<<endl;
			//if(n>100)
			//break;
		}
	}
	close_pcap(pd);
	delete g_Date;

	user_signal(10);
}
