#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <assert.h>
#include <inttypes.h>

#include "netflow_audit.h"
#include "date_time.h"

#define HAVE_PF_RING
#include <pfring.h>


using namespace std;
CDateTime *g_Date; 

void _hex_dump(const uint8_t *p,int len)
{
	int i=0;
	for(;i<len;i++)
	{
		printf("%02x ",p[i]);
		if((i+1)%16  == 0)
			cout<<endl;
	}
}

char *inaddr_2_ip(uint32_t addr)
{
	char *ip = NULL;
	struct in_addr inaddr;
	inaddr.s_addr = addr;//htonl
	ip = inet_ntoa(inaddr);

	return ip;
}
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

void coll_pcap_handle(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* pkt)
{
	assert(pkthdr!=NULL);
	cout<<"timeval:"<<pkthdr->ts.tv_sec<<"."<<pkthdr->ts.tv_usec<<endl;
	cout<<"time:"<<g_Date->timestamp_2_string(pkthdr->ts.tv_sec)<<endl;
	cout<<"caplen:"<<pkthdr->caplen<<endl;
	cout<<"len:"<<pkthdr->len<<endl;
	struct framehdr *fm = (struct framehdr*)pkt;
	cout<<"srcmac:"<<endl;
	_hex_dump(fm->srcmac,6);
	cout<<"dstmac:"<<endl;
	_hex_dump(fm->dstmac,6);
}

int main()
{
	pcap_t *pd = NULL;
	int ret = 0;
	cout<<g_Date->current_time()<<" hello NetFlow Audit\n";
	pd = open_pcap("ens33");

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
			cout<<"pcap_dispatch() no catch packges......\n";
		}
		else
		{
			n+=ret;
			cout<<"\nret:"<<ret<<endl;
			if(n>10)
			break;
		}
	}
	close_pcap(pd);
	delete g_Date;
}
