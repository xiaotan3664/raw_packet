#ifndef __UDPIO_H__
#define __UDPIO_H__
#include<winsock2.h>
#include<windows.h>

class UDPSocket {
public:
    UDPSocket(const unsigned char* addr = nullptr, unsigned short port = 0);
    int send(const unsigned char* data, int len);
    void setAddr(const unsigned char *addr, short port);

    ~UDPSocket();
private:
    unsigned char _addr[4];
    unsigned short _port;
    SOCKET _socket;
    SOCKADDR_IN _sockAddr;
};

//void wakeOnLan(const char* ifName, const unsigned char* ipAddr,
//               const unsigned char* macAddr_= nullptr);

#endif
