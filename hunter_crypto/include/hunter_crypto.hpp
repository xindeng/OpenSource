#include <Python.h>
#include <boost/python.hpp>
#include "hunter_gcm.hpp"

struct  Crypto
{
    string Encode(char* sIn,const int in_len, char* sKey, char* sIV);  
    string Decode(char * sIn, const int in_len, char* sKey, char* sIV, char*sMAC);
};