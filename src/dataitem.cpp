#include "dataitem.h"
#include "commonutils.h"

int DataItem::next_id = 0;
DataItemPtr makeDataItem(unsigned char* data, size_t len){
    return std::make_shared<DataItem>(data, len);
}

DataItemPtr makeDataItemByStr(const std::string& hexStr, int base){
    auto item = makeDataItem();
    item->fromString(hexStr, base);
    return item;
}

DataItemPtr allocDataItem(size_t len){
    auto data = new unsigned char[len];
    return makeDataItem(data, len);
}

DataItemPtr copyDataItem(const unsigned char *data, size_t len)
{
    auto d = allocDataItem(len);
    memcpy(d->data, data, len);
    return d;
}
static unsigned char char2num(char ch)
{
    if(ch>='a' && ch<='f') {
        ch = ch - 'a' + 10;
    } else if(ch>= 'A' && ch<='F') {
        ch = ch - 'A' + 10;
    } else if(ch>= '0' && ch <= '9'){
        ch = ch - '0';
    } else {
        ch = 255;
    }
    return ch;
}

std::string DataItem::toHexString(const char joinChar)
{
    return arrayToHexString(data, len, true, joinChar);
}

bool DataItem::fromHexString(const std::string& content)
{
    auto payload = new unsigned char[content.size()];
    auto payload_index = 0;
    unsigned char preValue = -1;
    for(auto ch: content){
        auto v = char2num(ch);
        if(v==255){
            if(preValue==255){
                continue;
            } else {
                payload[payload_index++] = preValue;
                preValue = 255;
            }
        } else {
            if(preValue==255){
                preValue = v;
            } else {
                payload[payload_index++] = (preValue<<4) | v;
                preValue = 255;
            }
        }
    }
    if(payload_index == 0){
        delete []payload;
        payload = nullptr;
    }
    if(data){
        delete []data;
    }
    data = payload;
    len = payload_index;
    return payload_index;
}

bool DataItem::fromString(const std::string &content, int base)
{
    auto payload = new unsigned char[content.size()];
    auto payload_index = 0;
    unsigned int value = 0;
    unsigned int v = 0;
    for(auto ch: content){
        auto v = char2num(ch);
        if(v<0 || v>=base){
            payload[payload_index++] = value;
            value = 0;
            v = -1;
        } else {
            value = value*base+v;
        }
    }
    if(v>=0 && v<base){
        payload[payload_index++] = value;
    }
    if(payload_index == 0){
        delete []payload;
        payload = nullptr;
    }
    if(data){
        delete []data;
    }
    data = payload;
    len = payload_index;
    return payload_index;
}

DataItem::~DataItem(){
    if(data){
        delete [] data;
    }
}
