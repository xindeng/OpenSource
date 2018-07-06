#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <iostream>

using std::string;

int EncodeSymmetry(const unsigned char * buf_in, const int in_len, const string & sKey, const string & sIV, char * buf_out, int & out_len, string & sMAC);
int DecodeSymmetry(const unsigned char * buf_in, const int in_len, const string & sKey, const string & sIV, const string & sMAC, char * buf_out, int & out_len);

int EncodeSymmetry(const string & sIn, const string & sKey, const string & sIV, string & sOut, string & sMAC);
int DecodeSymmetry(const string & sIn, const string & sKey, const string & sIV, const string & sMAC, string & sOut);
