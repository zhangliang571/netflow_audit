#ifndef __ETHERTYPE_H__
#define __ETHERTYPE_H__

#define ETHER_HDRLEN 14

#define ETHERTYPE_LEN           2
#define ETHERTYPE_GRE_ISO       0x00FE  /* not really an ethertype only used in GRE */
#define	ETHERTYPE_PUP		0x0200	/* PUP protocol */
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */
#define ETHERTYPE_NS		0x0600
#define	ETHERTYPE_SPRITE	0x0500
#define ETHERTYPE_TRAIL		0x1000
#define	ETHERTYPE_MOPDL		0x6001
#define	ETHERTYPE_MOPRC		0x6002
#define	ETHERTYPE_DN		0x6003
#define	ETHERTYPE_LAT		0x6004
#define ETHERTYPE_SCA		0x6007
#define ETHERTYPE_TEB		0x6558
#define	ETHERTYPE_LANBRIDGE	0x8038
#define	ETHERTYPE_DECDNS	0x803c
#define	ETHERTYPE_DECDTS	0x803e
#define	ETHERTYPE_VEXP		0x805b
#define	ETHERTYPE_VPROD		0x805c
#define ETHERTYPE_ATALK		0x809b
#define ETHERTYPE_AARP		0x80f3
#define	ETHERTYPE_TIPC		0x88ca
#define	ETHERTYPE_8021Q		0x8100
#define	ETHERTYPE_8021Q9100	0x9100
#define	ETHERTYPE_8021Q9200	0x9200
#define	ETHERTYPE_8021QinQ      0x88a8
#define ETHERTYPE_IPX		0x8137
#define ETHERTYPE_IPV6		0x86dd
#define	ETHERTYPE_PPP		0x880b
#define	ETHERTYPE_MPCP		0x8808
#define	ETHERTYPE_SLOW		0x8809
#define	ETHERTYPE_MPLS		0x8847
#define	ETHERTYPE_MPLS_MULTI	0x8848
#define ETHERTYPE_PPPOED	0x8863
#define ETHERTYPE_PPPOES	0x8864
#define ETHERTYPE_PPPOED2	0x3c12
#define ETHERTYPE_PPPOES2	0x3c13
#define ETHERTYPE_MS_NLB_HB	0x886f /* MS Network Load Balancing Heartbeat */
#define ETHERTYPE_JUMBO         0x8870
#define ETHERTYPE_LLDP          0x88cc
#define ETHERTYPE_EAPOL  	0x888e
#define ETHERTYPE_RRCP  	0x8899
#define	ETHERTYPE_LOOPBACK	0x9000
#define	ETHERTYPE_VMAN	        0x9100 /* Extreme VMAN Protocol */ 
#define	ETHERTYPE_CFM_OLD       0xabcd /* 802.1ag depreciated */
#define	ETHERTYPE_CFM           0x8902 /* 802.1ag */
#define	ETHERTYPE_ISO           0xfefe  /* nonstandard - used in Cisco HDLC encapsulation */
#define	ETHERTYPE_CALM_FAST     0x1111  /* ISO CALM FAST */
#define	ETHERTYPE_GEONET_OLD    0x0707  /* ETSI GeoNetworking (before Jan 2013) */
#define	ETHERTYPE_GEONET        0x8947  /* ETSI GeoNetworking (Official IEEE registration from Jan 2013) */

#define IPPROTO_IPV4		4
#if 0
#define	IPPROTO_IP		0		/* dummy for IP */
#define IPPROTO_HOPOPTS		0		/* IPv6 hop-by-hop options */
#define	IPPROTO_ICMP		1		/* control message protocol */
#define	IPPROTO_IGMP		2		/* group mgmt protocol */
#define	IPPROTO_TCP		6		/* tcp */
#define	IPPROTO_EGP		8		/* exterior gateway protocol */
#define IPPROTO_PIGP		9
#define	IPPROTO_UDP		17		/* user datagram protocol */
#define	IPPROTO_DCCP		33		/* datagram congestion control protocol */
#define IPPROTO_IPV6		41
#define IPPROTO_ROUTING		43		/* IPv6 routing header */
#define IPPROTO_FRAGMENT	44		/* IPv6 fragmentation header */
#define IPPROTO_RSVP		46 		/* resource reservation */
#define	IPPROTO_GRE		47		/* General Routing Encap. */
#define	IPPROTO_ESP		50		/* SIPP Encap Sec. Payload */
#define	IPPROTO_AH		51		/* SIPP Auth Header */
#define IPPROTO_MOBILE		55
#define IPPROTO_ICMPV6		58		/* ICMPv6 */
#define IPPROTO_NONE		59		/* IPv6 no next header */
#define IPPROTO_DSTOPTS		60		/* IPv6 destination options */
#define IPPROTO_MOBILITY_OLD	62
#define	IPPROTO_ND		77		/* Sun net disk proto (temp.) */
#define	IPPROTO_EIGRP		88		/* Cisco/GXS IGRP */
#define IPPROTO_OSPF		89
#define IPPROTO_PIM		103
#define IPPROTO_IPCOMP		108
#define IPPROTO_VRRP		112
#define IPPROTO_CARP		112
#define IPPROTO_PGM             113
#define IPPROTO_SCTP		132
#define IPPROTO_MOBILITY	135
#endif


#endif
