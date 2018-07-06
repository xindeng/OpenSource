#include "hunter_crypto.hpp"


string Crypto::Encode(char * sIn,const int in_len, char* sKey, char* sIV){
    unsigned char * usIn = (unsigned char *)sIn;
    string sMAC = "";
    int out_len = in_len+100;
    char * sOut = new char[out_len];
    memset(sOut, 0, out_len);
    int ret = EncodeSymmetry(usIn,in_len,sKey,sIV,sOut,out_len,sMAC);

    int iResLen = 16 + out_len;
    char *sResult = new char [iResLen];
    memset(sResult, 0, iResLen);
    memcpy(sResult, sMAC.data(), 16);
    memcpy(sResult + 16, sOut, out_len);

    //返回信息=16位消息验证码+加密内容
    string sRes((const char *)sResult, iResLen);    
    delete [] sOut;
    delete []sResult;
    return sRes;
}

string Crypto:: Decode(char * sIn, const int in_len, char* sKey, char* sIV, char*sMAC){
    int out_len = in_len+100;
    unsigned char * usIn = (unsigned char *)sIn;
    char * sOut = new char[out_len];
    memset(sOut, 0, out_len);
    int ret = DecodeSymmetry(usIn, in_len, sKey, sIV, sMAC, sOut, out_len);
    string sRes((const char*)sOut, out_len);

    delete []sOut;
    return sRes;
}



BOOST_PYTHON_MODULE(hunter_crypto)
{
    using namespace boost::python;
    class_<Crypto>("Crypto", init<>())  //导出C++构造函数
                .def("Encode",&Crypto::Encode)
                .def("Decode",&Crypto::Decode)
            ;
}
