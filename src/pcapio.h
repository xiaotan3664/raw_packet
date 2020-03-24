#ifndef PCAPIO_H
#define PCAPIO_H
#include <pcap.h>
#include "commonutils.h"
#include "dataitem.h"
#include <vector>
#include <thread>

#define MAX_FRAME_LEN 4096
typedef int (*pcapio_callback)(const unsigned char* data, int len, void* userdata);
class PCapIO
{
public:
    explicit PCapIO(const std::string& name = "");
    virtual ~PCapIO();
    bool setDevice(const std::string& name);
    bool setDevice(int index);

    // BaseIO interface
public:
    int broadcast(DataItemPtr frame);
    int send(DataItemPtr frame);
    bool startReceive(pcapio_callback callback, void* userdata);
    void stopReceive();
    virtual void setReceived(const unsigned char *data, int len);

    std::vector<std::string> allDescs() const;
    std::vector<std::string> allNames() const;

    bool needLog() const;
    void setNeedLog(bool needLog);
    bool isReceiving();
    int returnCode() const;

private:
    void reset();
    void findAllDevices();

private:
    pcap_t *_handle;
    char _errorBuf[PCAP_ERRBUF_SIZE];
    std::string _deviceName;
    std::vector<std::string> _allDescs;
    std::vector<std::string> _allNames;
    bool _needLog;
    pcapio_callback _callback = nullptr;
    std::thread recvThread;
    void* _userdata = nullptr;
    bool _isReceiving = false;
    int _returnCode = 0;

static  void pcap_callback(u_char *, const struct pcap_pkthdr *, const u_char *);
};

int getAdapterMacAddr(const char *lpszAdapterName, unsigned char* ucMacAddr);
int getAdapterIPAddr(const char *name, unsigned char* addr);
int getAdapterNetAddr(const char *name, unsigned int* netAddr, unsigned int* netMask);

int getMacByArp(const char* srcName, const unsigned char* ipAddr, unsigned char* macAddr);
#endif // PCAPIO_H
