#include "hunter_gcm.hpp"


 int EncodeSymmetry(const string & sIn, const string & sKey, const string & sIV, string & sOut, string & sMAC)
 	{
 		int iRet = -1;
 		int iOutLen = 0;
 		int iResLen = 0;
 		EVP_CIPHER_CTX oCtx;

// 		// 初始化
 		EVP_CIPHER_CTX_init(&oCtx);		// 初始化上下文

 		do {
 			iRet = EVP_EncryptInit_ex(&oCtx, EVP_aes_128_gcm(), NULL, NULL, NULL);		// 设置加密类型和操作模式
 			if (iRet != 1)
 				break;

 			iRet = EVP_CIPHER_CTX_ctrl(&oCtx, EVP_CTRL_GCM_SET_IVLEN, (int)sIV.length(), NULL);	// 设置IV的长度，默认是96 bits
 			if (iRet != 1)
 				break;

 			iRet = EVP_EncryptInit_ex(&oCtx, NULL, NULL, (const unsigned char *)sKey.data(), (const unsigned char *)sIV.data());				// 初始化密钥和IV
 			if (iRet != 1)
 				break;

// 			// 加密
 			size_t iReserveLen = sIn.length() + EVP_CIPHER_block_size(oCtx.cipher);
 			sOut.reserve(iReserveLen);
 			sOut.resize(iReserveLen);
 			unsigned char * pcOut = (unsigned char *)sOut.data();
 			iRet = EVP_EncryptUpdate(&oCtx, pcOut, &iOutLen, (const unsigned char *)sIn.data(), (int)sIn.length());		// 加密明文
 			if (iRet != 1)
 				break;

 			iResLen = iOutLen;

 			iRet = EVP_EncryptFinal_ex(&oCtx, pcOut + iResLen, &iOutLen);
 			if (iRet != 1)
 				break;

 			iResLen += iOutLen;
 			sOut.resize(iResLen);

 			// 创建TAG
 			sMAC.reserve(16);
 			sMAC.resize(16);
 			unsigned char * pcMac = (unsigned char *)sMAC.data();
 			iRet = EVP_CIPHER_CTX_ctrl(&oCtx, EVP_CTRL_GCM_GET_TAG, 16, pcMac);		// 获取TAG
 			if (iRet != 1)
 				break;

		} while (0);

		EVP_CIPHER_CTX_cleanup(&oCtx);
		return ((1 == iRet) ? 0 : -1);
	}


int DecodeSymmetry(const string & sIn, const string & sKey, const string & sIV, const string & sMAC, string & sOut)
	{
		int iRet = -1;
		int iOutLen = 0;
		int iResLen = 0;
		EVP_CIPHER_CTX oCtx;

		// 初始化
		EVP_CIPHER_CTX_init(&oCtx);		// 初始化上下文

		do {
			iRet = EVP_DecryptInit_ex(&oCtx, EVP_aes_128_gcm(), NULL, NULL, NULL);		// 设置加密类型和操作模式
			if (iRet != 1)
				break;

			iRet = EVP_CIPHER_CTX_ctrl(&oCtx, EVP_CTRL_GCM_SET_IVLEN, (int)sIV.length(), NULL);	// 设置IV长度
			if (iRet != 1)
				break;

			iRet = EVP_DecryptInit_ex(&oCtx, NULL, NULL, (const unsigned char *)sKey.data(), (const unsigned char *)sIV.data());				// 设置密钥和IV
			if (iRet != 1)
				break;

			// 解密
			size_t iReserveLen = sIn.length() + EVP_CIPHER_block_size(oCtx.cipher);
			sOut.reserve(iReserveLen);
			sOut.resize(iReserveLen);
			unsigned char * pcOut = (unsigned char *)sOut.data();
			EVP_DecryptUpdate(&oCtx, pcOut, &iOutLen, (const unsigned char *)sIn.data(), (int)sIn.length());	// 解密
			iResLen = iOutLen;

			// 校验TAG
			iRet = EVP_CIPHER_CTX_ctrl(&oCtx, EVP_CTRL_GCM_SET_TAG, (int)sMAC.length(), (void *)sMAC.data());	// 设置TAG值
			if (iRet == 1)
			{
				iRet = EVP_DecryptFinal_ex(&oCtx, pcOut + iResLen, &iOutLen);		// 校验TAG值
				if (iRet == 1)
				{
					iResLen += iOutLen;
					sOut.resize(iResLen);
				}
			}

		} while (0);

		EVP_CIPHER_CTX_cleanup(&oCtx);
		return ((1 == iRet) ? 0 : -1);
	}

int EncodeSymmetry(const unsigned char * buf_in, const int in_len, const string & sKey, const string & sIV, char * buf_out, int & out_len, string & sMAC)
	{
		if (!buf_in || 0 >= in_len || sKey.empty() || sIV.empty() || !buf_out || 0 >= out_len)
		{
			return -1;
		}
		int iRet = -1;
		int iOutLen = 0;
		int iResLen = 0;
		EVP_CIPHER_CTX oCtx;

		// 初始化
		EVP_CIPHER_CTX_init(&oCtx);		// 初始化上下文

		do {
			//printf("start EVP_EncryptInit_ex\r\n");
			iRet = EVP_EncryptInit_ex(&oCtx, EVP_aes_128_gcm(), NULL, NULL, NULL);		// 设置加密类型和操作模式
			if (iRet != 1)
				break;

			//printf("start EVP_CIPHER_CTX_ctrl\r\n");
			iRet = EVP_CIPHER_CTX_ctrl(&oCtx, EVP_CTRL_GCM_SET_IVLEN, (int)sIV.length(), NULL);	// 设置IV的长度，默认是96 bits
			if (iRet != 1)
				break;

			//printf("start EVP_EncryptInit_ex\r\n");
			iRet = EVP_EncryptInit_ex(&oCtx, NULL, NULL, (const unsigned char *)sKey.data(), (const unsigned char *)sIV.data());				// 初始化密钥和IV
			if (iRet != 1)
				break;

			// 加密
			int iReserveLen = in_len + EVP_CIPHER_block_size(oCtx.cipher);
			//printf("iReserveLen = %d\r\n", iReserveLen);
			if (iReserveLen > out_len)
			{
				iRet = -1;
				break;
			}

			unsigned char * pcOut = (unsigned char *)buf_out;
			//printf("start encrpyt\r\n");
			iRet = EVP_EncryptUpdate(&oCtx, pcOut, &iOutLen, (const unsigned char *)buf_in, in_len);		// 加密明文
			if (iRet != 1)
				break;

			iResLen = iOutLen;

			iRet = EVP_EncryptFinal_ex(&oCtx, pcOut + iResLen, &iOutLen);
			if (iRet != 1)
				break;

			iResLen += iOutLen;
			if (iResLen > out_len)
			{
				iRet = -1;
				break;
			}
			out_len = iResLen;

			// 创建TAG
			sMAC.reserve(16);
			sMAC.resize(16);
			unsigned char * pcMac = (unsigned char *)sMAC.data();
			iRet = EVP_CIPHER_CTX_ctrl(&oCtx, EVP_CTRL_GCM_GET_TAG, 16, pcMac);		// 获取TAG
			if (iRet != 1)
				break;

		} while (0);

		EVP_CIPHER_CTX_cleanup(&oCtx);
		return ((1 == iRet) ? 0 : -1);
}


int DecodeSymmetry(const unsigned char * buf_in, const int in_len, const string & sKey, const string & sIV, const string & sMAC, char * buf_out, int & out_len)
	{
		if (!buf_in || 0 >= in_len || sKey.empty() || sIV.empty() || sMAC.empty() || !buf_out || 0 >= out_len)
		{
			return -1;
		}
		int iRet = -1;
		int iOutLen = 0;
		int iResLen = 0;
		EVP_CIPHER_CTX oCtx;

		// 初始化
		EVP_CIPHER_CTX_init(&oCtx);		// 初始化上下文

		do {
			//printf("EVP_DecryptInit_ex\r\n");
			iRet = EVP_DecryptInit_ex(&oCtx, EVP_aes_128_gcm(), NULL, NULL, NULL);		// 设置加密类型和操作模式
			if (iRet != 1)
				break;
			//printf("EVP_CIPHER_CTX_ctrl\r\n");
			iRet = EVP_CIPHER_CTX_ctrl(&oCtx, EVP_CTRL_GCM_SET_IVLEN, (int)sIV.length(), NULL);	// 设置IV长度
			if (iRet != 1)
				break;
			//printf("EVP_DecryptInit_ex\r\n");
			iRet = EVP_DecryptInit_ex(&oCtx, NULL, NULL, (const unsigned char *)sKey.data(), (const unsigned char *)sIV.data());				// 设置密钥和IV
			if (iRet != 1)
				break;

			// 解密
			int iReserveLen = in_len + EVP_CIPHER_block_size(oCtx.cipher);
			//printf("iReserveLen > out_len\r\n");
			if (iReserveLen > out_len)
			{
				iRet = -1;
				break;
			}
			unsigned char * pcOut = (unsigned char *)buf_out;
			//printf("start EVP_DecryptUpdate\r\n");
			EVP_DecryptUpdate(&oCtx, pcOut, &iOutLen, (const unsigned char *)buf_in, in_len);	// 解密
			iResLen = iOutLen;

			// 校验TAG
			iRet = EVP_CIPHER_CTX_ctrl(&oCtx, EVP_CTRL_GCM_SET_TAG, (int)sMAC.length(), (void *)sMAC.data());	// 设置TAG值
			if (iRet == 1)
			{
				iRet = EVP_DecryptFinal_ex(&oCtx, pcOut + iResLen, &iOutLen);		// 校验TAG值
				if (iRet == 1)
				{
					iResLen += iOutLen;
					if (iResLen > out_len)
					{
						iRet = -1;
						break;
					}
					out_len = iResLen;
				}
			}

		} while (0);

		EVP_CIPHER_CTX_cleanup(&oCtx);
		return ((1 == iRet) ? 0 : -1);
}