#include <iostream>
#include "pcapio.h"
#include "frame_utils.h"
using namespace std;

int main_1(int argc, char *argv[])
{
    if(argc==1) {
        return -1;
    }
    return 0;
}
int main(int argc, char *argv[])
{
    if(argc==1) {
        return 0;
    }
    PCapIO pcap;
    pcap.setNeedLog(true);
    string cmd = argv[1];
    if(cmd == "list"){
        auto allNames = pcap.allNames();
        auto allDescs = pcap.allDescs();
        auto macAddr = allocDataItem(6);
        unsigned char ipAddr[4];
        int ipLen = 0;
        for(size_t i=0; i<allNames.size(); i++){
            getAdapterMacAddr(allNames[i].c_str(), macAddr->data);
            ipLen = getAdapterIPAddr(allNames[i].c_str(), ipAddr);
            cout<<i<<": "<<allNames[i]
                  <<": "<<macAddr->toHexString('-')
                  <<": "<<arrayToHexString(ipAddr, ipLen)
                  <<": "<<allDescs[i]<<endl;
        }
        return 0;
    }
    if(cmd == "send"){
        if(argc<4) return -1;
        int deviceId = atoi(argv[2]);
        string frameStr = argv[3];
        DataItemPtr frame = makeDataItemByStr(frameStr);
        if(!pcap.setDevice(deviceId)) return -1;
        return pcap.send(frame);
    }
    if(cmd == "wol"){
        if(argc<4) return -1;
        string ipStr = argv[2];
        DataItemPtr ipAddr = makeDataItemByStr(ipStr, 10);
        if(ipAddr->len != 4){
            return -1;
        }
        string macStr = argv[3];
        DataItemPtr macAddr = makeDataItemByStr(macStr, 16);
        wakeOnLan(macAddr->data, ipAddr->data);
    }
    if(cmd == "arp"){
        if(argc<4) return -1;
        int interfaceId = atoi(argv[2]);
        auto interfaceName = pcap.allNames()[interfaceId];
        auto ipAddr = makeDataItemByStr(argv[3], 10);
        unsigned char macAddr[6];
        if(getMacByArp(interfaceName.c_str(), ipAddr->data, macAddr) == 6){
            cout<<"ip: "<<ipAddr->toHexString('.')
                <<" mac: "<<arrayToHexString(macAddr, 6, true, '-')<<endl;
        } else {
            cout<<"cannot get mac addr for ip: "<<ipAddr->toHexString('.')<<endl;
        }
    }
    return 0;
}
