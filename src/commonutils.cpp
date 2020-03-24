#include<string>
#include "commonutils.h"
using namespace std;

static char valueToChar(unsigned char num, bool upperCase){
    if(num>=0 && num<=9){
        return '0'+num;
    } else if(num>=0xA && num<=0xF){
        return ((upperCase?'A':'a')+(num-0xA));
    }
    return -1;
}

string arrayToHexString(const unsigned char *data, size_t len, bool upperCase, char joinChar)
{
    if(len==0) return "";
    string result(len*3-1, joinChar);
    for(size_t i=0; i<len; i++){
        unsigned char ch = data[i];
        result[i*3] = valueToChar((ch>>4)&0x0F, upperCase);
        result[i*3+1] = valueToChar(ch&0x0F, upperCase);
    }
    return result;
}
