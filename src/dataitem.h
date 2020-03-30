#ifndef DATAITEM_H
#define DATAITEM_H
#include<memory>
#include<string>

struct DataItem {
    DataItem(unsigned char* data= nullptr, size_t len = 0):data(data), len(len), id(next_id++){}
    std::string toHexString(const char joinChar=' ');
    bool fromHexString(const std::string& content);
    bool fromString(const std::string& content, int base, int maxSeg);
    ~DataItem();
    unsigned char* data;
    size_t len;
    int id;
    static int next_id;
};

using DataItemPtr = std::shared_ptr<DataItem>;

DataItemPtr makeDataItem(unsigned char* data = nullptr, size_t len = 0);
DataItemPtr makeDataItemByStr(const std::string& frameStr, int base = 16);
DataItemPtr allocDataItem(size_t len);
DataItemPtr copyDataItem(const unsigned char* data, size_t len);

#endif // DATAITEM_H
