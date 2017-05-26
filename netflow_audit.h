#ifndef __NETFLOW_AUDIT_H__
#define __NETFLOW_AUDIT_H__


struct framehdr
{
	uint8_t srcmac[6];
	uint8_t dstmac[6];
	uint16_t ftype;
};

#endif

