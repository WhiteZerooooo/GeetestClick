import hashlib
import json
import math
import random
import time
import re

import httpx
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15


class Crack:
    def __init__(self, gt=None, challenge=None):
        self.pic_path = None
        self.s = None
        self.c = None
        self.session = httpx.Client(http2=True)
        self.session.headers = {
            "User-Agent": "x"
        }
        # self.session.verify = False
        self.gt = gt
        self.challenge = challenge
        self.aeskey = ''.join(f'{int((1 + random.random()) * 65536):04x}'[1:] for _ in range(4))
        public_key = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDB45NNFhRGWzMFPn9I7k7IexS5
XviJR3E9Je7L/350x5d9AtwdlFH3ndXRwQwprLaptNb7fQoCebZxnhdyVl8Jr2J3
FZGSIa75GJnK4IwNaG10iyCjYDviMYymvCtZcGWSqSGdC/Bcn2UCOiHSMwgHJSrg
Bm1Zzu+l8nSOqAurgQIDAQAB
-----END PUBLIC KEY-----'''
        self.public_key = serialization.load_pem_public_key(public_key.encode())
        self.enc_key = self.public_key.encrypt(self.aeskey.encode(), PKCS1v15()).hex()
        with open("mousepath.json", "r") as f:
            self.mouse_path = json.loads(f.read())

    def get_type(self) -> dict:
        url = f"https://api.geetest.com/ajax.php?gt={self.gt}&challenge={self.challenge}&lang=zh-cn&pt=0&client_type=web"
        res = self.session.get(url)
        return json.loads(res.text[1:-1])["data"]

    @staticmethod
    def encode(input_bytes: list):
        def get_char_from_index(index):
            char_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()"
            return char_table[index] if 0 <= index < len(char_table) else "."

        def transform_value(value, bit_mask):
            result = 0
            for r in range(23, -1, -1):
                if (bit_mask >> r) & 1:
                    result = (result << 1) + ((value >> r) & 1)
            return result

        encoded_string = ""
        padding = ""
        input_length = len(input_bytes)
        for i in range(0, input_length, 3):
            chunk_length = min(3, input_length - i)
            chunk = input_bytes[i:i + chunk_length]
            if chunk_length == 3:
                value = (chunk[0] << 16) + (chunk[1] << 8) + chunk[2]
                encoded_string += get_char_from_index(transform_value(value, 7274496)) + get_char_from_index(
                    transform_value(value, 9483264)) + get_char_from_index(
                    transform_value(value, 19220)) + get_char_from_index(transform_value(value, 235))
            elif chunk_length == 2:
                value = (chunk[0] << 16) + (chunk[1] << 8)
                encoded_string += get_char_from_index(transform_value(value, 7274496)) + get_char_from_index(
                    transform_value(value, 9483264)) + get_char_from_index(transform_value(value, 19220))
                padding = "."
            elif chunk_length == 1:
                value = chunk[0] << 16
                encoded_string += get_char_from_index(transform_value(value, 7274496)) + get_char_from_index(
                    transform_value(value, 9483264))
                padding = ".."
        return encoded_string + padding

    @staticmethod
    def MD5(text: str):
        return hashlib.md5(text.encode()).hexdigest()

    @staticmethod
    def encode_mouse_path(path: list, c: list, s: str):
        def preprocess(path: list):
            def BFIQ(e):
                t = 32767
                if not isinstance(e, int):
                    return e
                else:
                    if t < e:
                        e = t
                    elif e < -t:
                        e = -t
                return round(e)

            def BGAB(e):
                t = ''
                n = 0
                len(e or [])
                while n < len(e) and not t:
                    if e[n]:
                        t = e[n][4]
                    n += 1
                if not t:
                    return e
                r = ''
                i = ['mouse', 'touch', 'pointer', 'MSPointer']
                for s in range(len(i)):
                    if t.startswith(i[s]):
                        r = i[s]
                _ = list(e)
                for a in range(len(_) - 1, -1, -1):
                    c = _[a]
                    l = c[0]
                    if l in ['move', 'down', 'up']:
                        value = c[4] or ''
                        if not value.startswith(r):
                            _.pop(a)
                return _

            t = 0
            n = 0
            r = []
            s = 0
            if len(path) <= 0:
                return []
            o = None
            _ = None
            a = BGAB(path)
            c = len(a)
            for l in range(0 if c < 300 else c - 300, c):
                u = a[l]
                h = u[0]
                if h in ['down', 'move', 'up', 'scroll']:
                    if not o:
                        o = u
                    _ = u
                    r.append([h, [u[1] - t, u[2] - n], BFIQ(u[3] - s if s else s)])
                    t = u[1]
                    n = u[2]
                    s = u[3]
                elif h in ['blur', 'focus', 'unload']:
                    r.append([h, BFIQ(u[1] - s if s else s)])
                    s = u[1]
            return r

        def process(prepared_path: list):
            h = {
                'move': 0,
                'down': 1,
                'up': 2,
                'scroll': 3,
                'focus': 4,
                'blur': 5,
                'unload': 6,
                'unknown': 7
            }

            def p(e, t):
                n = bin(e)[2:]
                r = ''
                i = len(n) + 1
                while i <= t:
                    i += 1
                    r += '0'
                return r + n

            def d(e):
                t = []
                n = len(e)
                r = 0
                while r < n:
                    i = e[r]
                    s = 0
                    while True:
                        if s >= 16:
                            break
                        o = r + s + 1
                        if o >= n:
                            break
                        if e[o] != i:
                            break
                        s += 1
                    r += 1 + s
                    _ = h[i]
                    if s != 0:
                        t.append(_ | 8)
                        t.append(s - 1)
                    else:
                        t.append(_)
                a = p(n | 32768, 16)
                c = ''
                for l in range(len(t)):
                    c += p(t[l], 4)
                return a + c

            def g(e, tt):
                def temp1(e1):
                    n = len(e)
                    r = 0
                    i = []
                    while r < n:
                        s = 1
                        o = e[r]
                        _ = abs(o)
                        while True:
                            if n <= r + s:
                                break
                            if e[r + s] != o:
                                break
                            if (_ >= 127) or (s >= 127):
                                break
                            s += 1
                        if s > 1:
                            i.append((49152 if o < 0 else 32768) | s << 7 | _)
                        else:
                            i.append(o)
                        r += s
                    return i

                e = temp1(e)

                r = []
                i = []

                def n(e, t):
                    return 0 if e == 0 else math.log(e) / math.log(t)

                for temp in e:
                    t = math.ceil(n(abs(temp) + 1, 16))
                    if t == 0:
                        t = 1
                    r.append(p(t - 1, 2))
                    i.append(p(abs(temp), t * 4))

                s = ''.join(r)
                o = ''.join(i)

                def temp2(t):
                    return t != 0 and t >> 15 != 1

                def temp3(e1):
                    n = []

                    def temp(e2):
                        if temp2(e2):
                            n.append(e2)

                    for r in range(len(e1)):
                        temp(e1[r])
                    return n

                def temp4(t):
                    if t < 0:
                        return '1'
                    else:
                        return '0'

                if tt:
                    n = []
                    e1 = temp3(e)
                    for r in range(len(e1)):
                        n.append(temp4(e1[r]))
                    n = ''.join(n)
                else:
                    n = ''
                return p(len(e) | 32768, 16) + s + o + n

            def u(e):
                t = ''
                n = len(e) // 6
                for r in range(n):
                    t += '()*,-./0123456789:?@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~'[
                        int(e[6 * r: 6 * (r + 1)], 2)]
                return t

            t = []
            n = []
            r = []
            i = []
            for a in range(len(prepared_path)):
                _ = prepared_path[a]
                a = len(_)
                t.append(_[0])
                n.append(_[1] if a == 2 else _[2])
                if a == 3:
                    r.append(_[1][0])
                    i.append(_[1][1])
            c = d(t) + g(n, False) + g(r, True) + g(i, True)
            l = len(c)
            if l % 6 != 0:
                c += p(0, 6 - l % 6)
            return u(c)

        def postprocess(e, t, n):
            i = 0
            s = e
            o = t[0]
            _ = t[2]
            a = t[4]
            while True:
                r = n[i:i + 2]
                if not r:
                    break
                i += 2
                c = int(r, 16)
                l = chr(c)
                u = (o * c * c + _ * c + a) % len(e)
                s = s[:u] + l + s[u:]
            return s

        return postprocess(process(preprocess(path)), c, s)

    def aes_encrypt(self, content: str):
        cipher = Cipher(algorithms.AES(self.aeskey.encode()), modes.CBC(b"0000000000000000"))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(content.encode())
        padded_data += padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return ct

    def get_c_s(self):
        res = self.session.get(f"https://api.geetest.com/get.php?is_next=true&type=click&gt={self.gt}&challenge={self.challenge}&lang=zh-cn&https=false&protocol=https://&offline=false&product=embed&api_server=api.geetest.com&isPC=true&autoReset=true&width=100%25&callback=geetest_{int(time.time() * 1000)}")
        data = json.loads(re.search(r'geetest_\d+\((.*)\)', res.text, re.DOTALL).group(1))
        pic = data["data"]['pic']
        c = data["data"]['c']
        s = data["data"]['s']
        self.pic_path = pic
        self.c = c
        self.s = s
        return c, s

    def get_pic(self,retry=0):
        pic_url = "https://static.geetest.com" + self.pic_path
        return self.session.get(pic_url).content

    def verify(self, points: list):
        u = self.enc_key
        o = {
            "lang": "zh-cn",
            "passtime": 1600,
            "a": ",".join(points),
            "pic": self.pic_path,
            "tt": self.encode_mouse_path(self.mouse_path, self.c, self.s),
            "ep": {
                "ca": [{"x": 524, "y": 209, "t": 0, "dt": 1819}, {"x": 558, "y": 299, "t": 0, "dt": 428},
                       {"x": 563, "y": 95, "t": 0, "dt": 952}, {"x": 670, "y": 407, "t": 3, "dt": 892}],
                "v": '3.1.0',
                "$_FB": False,
                "me": True,
                "tm": {"a": 1724585496403, "b": 1724585496605, "c": 1724585496613, "d": 0, "e": 0, "f": 1724585496404,
                       "g": 1724585496404, "h": 1724585496404, "i": 1724585496404, "j": 1724585496404, "k": 0,
                       "l": 1724585496413, "m": 1724585496601, "n": 1724585496603, "o": 1724585496618,
                       "p": 1724585496749, "q": 1724585496749, "r": 1724585496751, "s": 1724585498068,
                       "t": 1724585498068, "u": 1724585498069}
            },
            "h9s9": "1816378497",
        }
        o["rp"] = self.MD5(self.gt + self.challenge + str(o["passtime"]))
        o = json.dumps(o, separators=(',', ':'))
        # print(o)
        ct = self.aes_encrypt(o)
        s = []
        for byte in ct:
            s.append(byte)
        p = self.encode(s)
        w = p + u
        params = {
            "gt": self.gt,
            "challenge": self.challenge,
            "lang": "zh-cn",
            "pt": 0,
            "client_type": "web",
            "w": w
        }
        resp = self.session.get("https://api.geevisit.com/ajax.php", params=params).text
        return resp[1:-1]
