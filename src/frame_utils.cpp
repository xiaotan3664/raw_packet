#include "commonutils.h"
#include "frame_utils.h"
#include "pcapio.h"

static unsigned short frameChecksum(const unsigned char* data, int len, unsigned short oldChecksum = -1){
    oldChecksum = BIG_LITTLE_SWAP16(oldChecksum);
    unsigned int highSum = 0;
    unsigned int lowSum = (unsigned short)(~oldChecksum);
    if(len == 0) return 0;
    if(len&1){
        highSum = data[len-1];
    }
    for(int i=0; i<len; i+=2){
        highSum += data[i];
        lowSum += data[i+1];
    }
    unsigned int checksum = (highSum<<8) + lowSum;
    while(checksum & 0xFFFF0000) checksum = (checksum>>16) + (checksum&0x0000FFFF);
    unsigned short finalChecksum = ~((short)checksum);
    finalChecksum = BIG_LITTLE_SWAP16(finalChecksum);
    return finalChecksum;
}

#pragma pack(1)
struct UdpHeader {
    unsigned short srcPort;
    unsigned short dstPort;
    unsigned short totalLen;  //this header and data len
    unsigned short checksum;
};
#pragma pack()

DataItemPtr genUdpPart(
        const unsigned short srcPort,
        const unsigned short dstPort,
        const unsigned char *data,
        int len) {
    int partLen = sizeof(UdpHeader) + len;
    DataItemPtr frame = allocDataItem(partLen);
    auto header = (UdpHeader*)frame->data;
    header->srcPort = BIG_LITTLE_SWAP16(srcPort);
    header->dstPort = BIG_LITTLE_SWAP16(dstPort);
    header->checksum = 0;
    header->totalLen = BIG_LITTLE_SWAP16(partLen);
    memcpy(frame->data + sizeof(UdpHeader), data, len);
    header->checksum = frameChecksum(frame->data, frame->len);
    return frame;
}

#pragma pack(1)
struct IPv4Header {
    unsigned char  ipHeaderLen:4;  //ip header length
    unsigned char  version:4;      //version
    unsigned char  typeOfService;  //type of service
    unsigned short totalLen;       //total length
    unsigned short id;             //identification
    unsigned short flagAndOffset;  //reserved, notfrag, morefrag, fragment offset
    unsigned char  timeToLive;     //time to live
    unsigned char  protocol;       //protocol type
    unsigned short checksum;       //checksum
    unsigned int   srcAddr;        //source address
    unsigned int   dstAddr;        //destination address
};
struct PseudoHeader{
    unsigned int   srcAddr;        //source address
    unsigned int   dstAddr;        //destination address
    unsigned char  zeros;
    unsigned char  protocal;
    unsigned short totalLen;        //destination address
};
#pragma pack()
DataItemPtr genIPv4Part(const unsigned char *srcIpAddr, const unsigned char *dstIpAddr,
                        const unsigned char *data, int len, unsigned char protocol)
{
    int totalLen = sizeof(IPv4Header) + len;
    auto frame = allocDataItem(totalLen);
    auto ipHeader = (IPv4Header*)frame->data;
    ipHeader->ipHeaderLen = sizeof(IPv4Header)/4;
    ipHeader->version = 4;
    ipHeader->typeOfService = 0;
    ipHeader->totalLen = BIG_LITTLE_SWAP16(totalLen);
    ipHeader->id = 0;
    ipHeader->flagAndOffset = 0;
    ipHeader->flagAndOffset = 1<<14;
    ipHeader->flagAndOffset = BIG_LITTLE_SWAP16(ipHeader->flagAndOffset);
    ipHeader->timeToLive = 64;
    ipHeader->protocol = protocol;
    memcpy(&ipHeader->srcAddr, srcIpAddr, sizeof(ipHeader->srcAddr));
    memcpy(&ipHeader->dstAddr, dstIpAddr, sizeof(ipHeader->dstAddr));
    memcpy(frame->data+sizeof(IPv4Header), data, len);
    if(protocol == IP_UDP_PROTOCOL){
        auto udpHeader = (UdpHeader*)(frame->data + sizeof(IPv4Header));
        PseudoHeader pHeader;
        pHeader.dstAddr = ipHeader->dstAddr;
        pHeader.srcAddr = ipHeader->srcAddr;
        pHeader.protocal = protocol;
        pHeader.zeros = 0;
        pHeader.totalLen = udpHeader->totalLen;
        udpHeader->checksum = frameChecksum((const unsigned char*)&pHeader, sizeof(PseudoHeader), udpHeader->checksum);
    }
    ipHeader->checksum = 0;
    ipHeader->checksum = frameChecksum(frame->data, sizeof(IPv4Header));
    return frame;
}

#pragma pack(1)
struct EthHeader {
    unsigned char dstAddr[6];
    unsigned char srcAddr[6];
    unsigned short type;
};
#pragma pack()
DataItemPtr genEthFrame(
        const unsigned char *srcMacAddr,
        const unsigned char *dstMacAddr,
        unsigned short type,
        const unsigned char *data, int len) {
    int totalLen = sizeof(EthHeader) + len;
    auto frame = allocDataItem(totalLen);
    auto ethHeader = (EthHeader*)frame->data;
    memcpy(&ethHeader->dstAddr, dstMacAddr, sizeof(ethHeader->dstAddr));
    memcpy(&ethHeader->srcAddr, srcMacAddr, sizeof(ethHeader->srcAddr));
    ethHeader->type = type;
    memcpy(frame->data + sizeof(EthHeader), data, len);
    return frame;
}

void wakeOnLan(const unsigned char *dstMacAddr, const unsigned char *dstIpAddr)
{
    auto content = allocDataItem(6+6*16);
    for(int i=0; i<6; i++){
        content->data[i] = 0xFF;
    }
    for(int i=0; i<16; i++){
        memcpy(&content->data[6+i*6], dstMacAddr, 6);
    }
    auto udpPart = genUdpPart(20000, 9, content->data, content->len);
    unsigned char srcIpAddr[4];
    unsigned char srcMacAddr[6];
    unsigned int* srcIpInt = (unsigned int*)srcIpAddr;
    unsigned int* dstIpInt = (unsigned int*)dstIpAddr;
    PCapIO pcap;
    pcap.setNeedLog(true);
    for(auto name: pcap.allNames()){
        if(getAdapterIPAddr(name.c_str(), srcIpAddr) != 4) continue;
        if(getAdapterMacAddr(name.c_str(), srcMacAddr) != 6) continue;
        unsigned int netMask, netAddr;
        if(getAdapterNetAddr(name.c_str(), &netAddr, &netMask)<0) continue;
        if((netMask&(*srcIpInt)) != (netMask&(*dstIpInt))) continue;

        auto ipPart = genIPv4Part(
                    srcIpAddr, dstIpAddr,
                    udpPart->data, udpPart->len, IP_UDP_PROTOCOL);
        auto macFrame = genEthFrame(
                    srcMacAddr, dstMacAddr,
                    ETH_IP_TYPE, ipPart->data, ipPart->len);
        pcap.setDevice(name);
        pcap.send(macFrame);
    }
}
