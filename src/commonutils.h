#ifndef COMMONUTILS_H
#define COMMONUTILS_H
#include <string>

#define BIG_LITTLE_SWAP16(A) ((((unsigned short)(A) & 0xff00) >> 8) | ((((unsigned short)(A)) & 0xff) << 8))
#define BIG_LITTLE_SWAP32(A) ((((unsigned int)(A) & 0xff000000) >> 24) | (((unsigned int)(A) & 0x00ff0000) >> 8) | (((unsigned int)(A) & 0x0000ff00) << 8)|(((unsigned int)(A) & 0x000000ff) << 24))

std::string arrayToHexString(const unsigned char* data, size_t len, bool upperCase = true, char joinChar = ' ');

#endif // COMMONUTILS_H
