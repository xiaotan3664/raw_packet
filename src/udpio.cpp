#include "udpio.h"
#include "pcapio.h"

#pragma comment(lib,"ws2_32.lib")
UDPSocket::UDPSocket(const unsigned char *addr, unsigned short port)
{
    int err;
    WORD wVersionRequested;
    WSADATA wsaData;
    wVersionRequested = MAKEWORD(1, 1);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        throw err;
    }
    if (LOBYTE(wsaData.wVersion) != 1 ||
            HIBYTE(wsaData.wVersion) != 1) {
        WSACleanup();
        throw;
    }
    _socket = socket(AF_INET, SOCK_DGRAM, 0);
    setAddr(addr, port);
}

int UDPSocket::send(const unsigned char *data, int len)
{
    return sendto(_socket, (const char*)data , len, 0, (SOCKADDR*)&_sockAddr, len);
}

void UDPSocket::setAddr(const unsigned char *addr, short port)
{
    if(addr == nullptr) return;
    memcpy(&_sockAddr.sin_addr.S_un.S_addr, addr, 4);
    _sockAddr.sin_family = AF_INET;
    _sockAddr.sin_port = htons(port);
}



UDPSocket::~UDPSocket()
{
    closesocket(_socket);
    WSACleanup();
}

//void wakeOnLan(const char* ifName, const unsigned char* ipAddr,
//               const unsigned char* macAddr_)
//{
//    unsigned char macAddr[6];
//    if(!macAddr_){
//        if(getMacByArp(ifName, ipAddr, macAddr) != 6){
//            throw "can not get mac addr";
//        }
//    } else {
//        memcpy(macAddr, macAddr_, 6);
//    }
//    auto frame = allocDataItem(6+6*16);
//    for(int i=0; i<6; i++){
//        frame->data[i] = 0xFF;
//    }
//    for(int i=0; i<16; i++){
//        memcpy(&frame->data[6+i*6], macAddr, sizeof(macAddr));
//    }
//    UDPSocket udpsock(ipAddr, 9);
//    udpsock.send(frame->data, frame->len);
//}
