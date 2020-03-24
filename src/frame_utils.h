#ifndef __FRAME_UTILS_H__
#define __FRAME_UTILS_H__
#include "dataitem.h"

DataItemPtr genUdpPart(
        const unsigned short srcPort,
        const unsigned short dstPort,
        const unsigned char* data,
        int len);

#define IP_UDP_PROTOCOL 0x11
DataItemPtr genIPv4Part(const unsigned char* srcIpAddr,
        const unsigned char* dstIpAddr,
        const unsigned char* data, int len, unsigned char protocol = IP_UDP_PROTOCOL);

#define ETH_IP_TYPE 0x0008
#define ETH_ARP_TYPE 0x0608

DataItemPtr genEthFrame(
        const unsigned char* srcMacAddr,
        const unsigned char* dstMacAddr,
        unsigned short type,
        const unsigned char* data, int len);

void wakeOnLan(
        const unsigned char* macAddr,
        const unsigned char* ipAddr);
#endif
