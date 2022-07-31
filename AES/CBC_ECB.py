#!/usr/bin/python3.6
# -*- coding: utf-8 -*-
#
# @Author  : Minshenyao
# @Email   : https://github.com/Minshenyao
# @Software: PyCharm
import base64
import binascii
from Crypto.Cipher import AES


class Crypto_tools:
    @staticmethod
    def pkcs7padding(text):
        if len(text.encode('utf-8')) % 16:
            add = 16 - (len(text.encode('utf-8')) % 16)
        else:
            add = 0
        text = text + ('\0' * add)
        return text.encode('utf-8')

    @staticmethod
    def pkcs7unpadding(text):
        return bytes.decode(text).rstrip('\0')


class Crypto_AES:
    @staticmethod
    def CBC_encrypt(text, key):
        """
        AES-CBC加密
        :param text:
        :param key:
        :return:
        """
        iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        text = Crypto_tools.pkcs7padding(text)
        text = cipher.encrypt(text)
        text = binascii.b2a_hex(text).decode('utf-8')
        # text = base64.b64encode(text).decode('utf-8')
        print(text)
        return text

    @staticmethod
    def CBC_decrypt(text, key):
        """
        AES-CBC解密
        :param text:
        :param key:
        :return:
        """
        iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        text = binascii.a2b_hex(text)
        # text = base64.b64decode(text)
        text = cipher.decrypt(text)
        text = Crypto_tools.pkcs7unpadding(text)
        print(text)
        return text

    @staticmethod
    def ECB_encrypt(text, key):
        """
        AES-ECB加密
        :param text:
        :param key:
        :return:
        """
        text = Crypto_tools.pkcs7padding(text)
        cryptos = AES.new(key.encode('utf-8'), AES.MODE_ECB)
        text = cryptos.encrypt(text)
        text = binascii.b2a_hex(text).decode('utf-8')
        # text = base64.b64encode(text).decode('utf-8')
        print(text)
        return text

    @staticmethod
    def ECB_decrypt(text, key):
        """
        AES-ECB解密
        :param text:
        :param key:
        :return:
        """
        cryptor = AES.new(key.encode('utf-8'), AES.MODE_ECB)
        text = binascii.a2b_hex(text)
        # text = base64.b64decode(text)
        text = cryptor.decrypt(text)
        text = Crypto_tools.pkcs7unpadding(text)
        print(text)
        return text


if __name__ == '__main__':
    C = Crypto_AES()
    a = C.ECB_encrypt('aaa', '1234567890123456')
    C.ECB_decrypt(a, '1234567890123456')
    a = C.CBC_encrypt('aaa', '1234567890123456')
    C.CBC_decrypt(a, '1234567890123456')

