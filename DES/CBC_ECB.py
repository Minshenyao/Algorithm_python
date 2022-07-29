#!/usr/bin/python3.6
# -*- coding: utf-8 -*-
#
# @Author  : Minshenyao
# @Email   : https://github.com/Minshenyao
# @Software: PyCharm
from pyDes import des, CBC, ECB, PAD_PKCS5
import base64
import binascii


class Crypto_DES:
    @staticmethod
    def CBC_encrypt(text: str, key: str) -> str:
        """
        DES-CBC加密
        :param text:
        :param key:
        :return:
        """
        iv = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        d = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        text = d.encrypt(text)
        text = binascii.b2a_hex(text).decode('utf-8')
        # text = base64.b64encode(text)
        # text = text.decode()
        print(text)
        return text

    @staticmethod
    def CBC_decrypt(text: str, key: str) -> str:
        """
        DBS-CEC解密
        :param text:
        :param key:
        :return:
        """
        iv = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        d = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        # text = base64.b64decode(text)
        text = binascii.a2b_hex(text)
        text = d.decrypt(text)
        text = text.decode()
        print(text)
        return text

    @staticmethod
    def ECB_encrypt(text: str, key: str) -> str:
        """
        DES-ECB加密
        :param text:
        :param key:
        :return:
        """
        iv = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        d = des(key, ECB, iv, pad=None, padmode=PAD_PKCS5)
        text = d.encrypt(text)
        text = binascii.b2a_hex(text).decode('utf-8')
        # text = base64.b64encode(text)
        # text = text.decode()
        print(text)
        return text

    @staticmethod
    def ECB_decrypt(text: str, key: str) -> str:
        """
        DES-ECB解密
        :param text:
        :param key:
        :return:
        """
        iv = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        d = des(key, ECB, iv, pad=None, padmode=PAD_PKCS5)
        # text = base64.b64decode(text)
        text = binascii.a2b_hex(text)
        text = d.decrypt(text)
        text = text.decode()
        print(text)
        return text


if __name__ == '__main__':
    C = Crypto_DES()
    string = 'aaa'
    passwd = '12345678'
    string = C.ECB_encrypt(string, passwd)
    C.ECB_decrypt(string, passwd)
    string = C.CBC_encrypt(string, passwd)
    C.CBC_decrypt(string, passwd)
