#include<iostream>
#include<winsock2.h>
#include<windows.h>
#include <ntddndis.h>
#define BPF_MAJOR_VERSION
#include <Packet32.h>
#include "pcapio.h"
using std::string;
using std::cout;
using std::cerr;
using std::endl;

PCapIO::PCapIO(const string& name) : _handle(nullptr)
{
    findAllDevices();
    setDevice(name);
    setNeedLog(false);
}

PCapIO::~PCapIO()
{
    reset();
}

bool PCapIO::setDevice(const string& name)
{
    if(name == "") return false;
    if(_needLog){
        cout<<"opening: "<<name<<endl;
    }
    if(name == _deviceName) return _handle != nullptr;
    auto new_handle = pcap_open_live(name.c_str(), 65535, 1,1000, _errorBuf);
    if(!new_handle){
        cerr<<_errorBuf<<endl;
        return false;
    }
    reset();
    _handle = new_handle;
    _deviceName = name;
    return true;
}

bool PCapIO::setDevice(int index)
{
    if(index<0) index += _allNames.size();
    if(index<0 || index>=(int)_allNames.size()){
        return false;
    }
    return setDevice(_allNames[index]);
}

int PCapIO::broadcast(DataItemPtr frame)
{
    string oldName = _deviceName;
    for(auto name: _allNames){
        if(setDevice(name)){
            send(frame);
        }
    }
    setDevice(oldName);
}

int PCapIO::send(DataItemPtr frame)
{
    if(needLog()){
        cout<<_deviceName<<" sending:"<<frame->toHexString()<<endl;
    }
    return pcap_sendpacket(_handle, frame->data, frame->len);
}

bool PCapIO::startReceive(pcapio_callback callback, void* userdata)
{
   if(!_handle) return false;
   if(_isReceiving) stopReceive();
   _callback = callback;
   _userdata = userdata;
   _isReceiving = true;
   recvThread = std::thread([this](){
       if(pcap_loop(this->_handle, -1, PCapIO::pcap_callback, (unsigned char*)this)<0){
           this->_isReceiving = false;
           return false;
       }
   });
   return true;
}

void PCapIO::stopReceive()
{
    pcap_breakloop(_handle);
    _isReceiving = false;
}

void PCapIO::setReceived(const unsigned char *data, int len)
{
    if(!_callback) stopReceive();
    if((_returnCode=_callback(data, len, _userdata))<0){
        stopReceive();
    }
}

void PCapIO::reset()
{
    if(_handle){
        pcap_breakloop(_handle);
        if(recvThread.joinable()){
            recvThread.join();
        }
        pcap_close(_handle);
        _handle = nullptr;
    }
}

void PCapIO::findAllDevices()
{
      pcap_if_t* allDevs;
      char errBuf[PCAP_ERRBUF_SIZE];
      if(pcap_findalldevs(&allDevs, errBuf) == -1){
          return;
      }
      for(auto d=allDevs; d!=nullptr; d=d->next){
          _allNames.push_back(d->name);
          _allDescs.push_back(d->description);
      }
      pcap_freealldevs(allDevs);
}

int PCapIO::returnCode() const
{
    return _returnCode;
}

bool PCapIO::needLog() const
{
    return _needLog;
}

void PCapIO::setNeedLog(bool needLog)
{
    _needLog = needLog;
}

bool PCapIO::isReceiving()
{
    return _isReceiving;
}

std::vector<std::string> PCapIO::allNames() const
{
    return _allNames;
}

std::vector<std::string> PCapIO::allDescs() const
{
    return _allDescs;
}

void PCapIO::pcap_callback(u_char * param, const pcap_pkthdr *hdr, const u_char * data)
{
    auto pcapIO = (PCapIO*)param;
    pcapIO->setReceived(data, hdr->caplen);
}

int getAdapterMacAddr(const char* lpszAdapterName, unsigned char* ucMacAddr)
{
    int result = -1;
    LPADAPTER lpAdapter = PacketOpenAdapter((PCHAR)lpszAdapterName );
    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)) {
        return result;
    }

    PPACKET_OID_DATA oidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
    if ( NULL == oidData ) {
        PacketCloseAdapter(lpAdapter);
        return result;
    }

    oidData->Oid = OID_802_3_CURRENT_ADDRESS;
    oidData->Length = 6;
    memset(oidData->Data, 0, 6);

    BOOLEAN  bStatus = PacketRequest(lpAdapter, FALSE, oidData);
    if (bStatus) {
        for (int i = 0; i < 6; ++i) {
            ucMacAddr[i] = (oidData->Data)[i];
        }
        result = 6;
    } else {
        free(oidData);
        return result;
    }
    free(oidData);
    PacketCloseAdapter(lpAdapter);
    return result;
}

int getAdapterIPAddr(const char *name, unsigned char* addr){
      pcap_if_t* allDevs;
      char errBuf[PCAP_ERRBUF_SIZE];
      if(pcap_findalldevs(&allDevs, errBuf) == -1){
          return 0;
      }
      for(auto d=allDevs; d!=nullptr; d=d->next){
          if(strcmp(d->name, name) != 0) continue;
          for(auto a=d->addresses; a; a=a->next){
              if(a->addr->sa_family == AF_INET){
                  auto ipAddr = (((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
                  memcpy(addr, &ipAddr, 4);
                  pcap_freealldevs(allDevs);
                  return 4;
              }
          }
      }
      pcap_freealldevs(allDevs);
      return 0;
}

int getAdapterNetAddr(const char *name, unsigned int* netAddr, unsigned int* netMask)
{
    char error_content[PCAP_ERRBUF_SIZE];
    auto res = pcap_lookupnet(name, netAddr, netMask,error_content);
    return res>=0;
}

struct ArpCallbackStruct {
    const unsigned char* queryIpAddr;
    unsigned char* macAddr;
    int recvCount=0;
};

#define ARP_OPCODE_OFFSET (6+6+9)
#define ARP_FRAME_LEN 42
#define ARP_SENDER_MAC_OFFSET (6+6+10)
#define ARP_SENDER_IP_OFFSET (6+6+16)
static int arp_callback(const unsigned char* data, int len, void* userdata){
   auto arpInfo = (ArpCallbackStruct*)userdata;
   arpInfo->recvCount++;
   if(len < ARP_FRAME_LEN) return 1;
   if(data[6+6+0] != 0x08) return 1;
   if(data[6+6+1] != 0x06) return 1;
   if(data[ARP_OPCODE_OFFSET] != 0x02) return 1;
   if(arpInfo->recvCount >=10){
       return -1;
   }
   if(memcmp(arpInfo->queryIpAddr, &data[ARP_SENDER_IP_OFFSET], 4)!=0) return 1;
   memcpy(arpInfo->macAddr, &data[ARP_SENDER_MAC_OFFSET], 6);
   cout<<"get "<<arrayToHexString(arpInfo->queryIpAddr,4, true, '.')
      <<" mac "<<arrayToHexString(arpInfo->macAddr, 6, true, ':')<<endl;
   return -6;
}

int getMacByArp(const char *name, const unsigned char *ipAddr,
                unsigned char *macAddr)
{
   DataItemPtr frame = allocDataItem(ARP_FRAME_LEN);
   unsigned char* arpQueryFrame = frame->data;
   for(int i=0; i<6; i++){
       arpQueryFrame[i] = 0xFF;
   }
   if(getAdapterMacAddr(name, &arpQueryFrame[6]) != 6){
       return -1;
   }
   //mac type
   arpQueryFrame[6+6+0] = 0x08;
   arpQueryFrame[6+6+1] = 0x06;
   //add type: ethernet
   arpQueryFrame[6+6+2] = 0x00;
   arpQueryFrame[6+6+3] = 0x01;
   //ipv4
   arpQueryFrame[6+6+4] = 0x08;
   arpQueryFrame[6+6+5] = 0x00;
   //mac len
   arpQueryFrame[6+6+6] = 0x06;
   //ip len
   arpQueryFrame[6+6+7] = 0x04;
   //arp op code: 1 arp request, 2 arp response,
   //             3: rarp request, 4 rarp response
   arpQueryFrame[6+6+8] = 0x00;
   arpQueryFrame[ARP_OPCODE_OFFSET] = 0x01;

   memcpy(&arpQueryFrame[6+6+10], &arpQueryFrame[6], 6);

   if(getAdapterIPAddr(name, &arpQueryFrame[6+6+16]) != 4){
       return -1;
   }
   for(int i=0; i<6; i++){
       arpQueryFrame[6+6+20+i] = 0;
   }
   for(int i=0; i<4; i++){
       arpQueryFrame[6+6+26+i] = ipAddr[i];
   }

   PCapIO pcap;
   ArpCallbackStruct arpInfo{ipAddr, macAddr, 0};
   if(!pcap.setDevice(name)) return -1;
   pcap.startReceive(arp_callback, &arpInfo);
   pcap.send(frame);
   int waitCount = 0;
   while(waitCount<100){
       waitCount++;
       if(!pcap.isReceiving()) break;
       std::this_thread::sleep_for(std::chrono::milliseconds(200));
   }
   return -pcap.returnCode();
}
