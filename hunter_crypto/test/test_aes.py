# coding=utf-8
import hunter_crypto

aes = hunter_crypto.Crypto()


def hunter_encrypt(key, iv, plaintext):
    """
    AES-GCM加密
    :param key:密钥
    :param iv:加密向量
    :param plaintext:待加密的文件二进制六
    :return:tag:消息验证码，加密完成的二进制流
    """

    ret = aes.Encode(plaintext, len(plaintext), key, iv)
    tag = ret[:16]
    ciphertext = ret[16:]
    return tag, ciphertext


def hunter_decrypt(key, iv, tag, ciphertext):
    """
    解密二进制流
    :param key:加密密钥
    :param iv: 随机向量
    :param tag: 消息验证码
    :param ciphertext: 待解密的二进制流
    :return:解密成功的二进制流
    """
    v = aes.Decode(ciphertext, len(ciphertext), key, iv, tag)
    return v


if __name__ == '__main__':
    with open('test_aes.py', 'rb') as f:
        text = f.read()
        key = '123456890123456'
        iv = key
        tag, ciphertext = hunter_encrypt(key, iv, text)
        content = hunter_decrypt(key, iv, tag, ciphertext)
        print("descrypto content:", content[0:20])
