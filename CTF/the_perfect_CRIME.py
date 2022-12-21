# CRIME Attack:

from library import util_classes as util

import string
import sys

conn : util.ctf_connection = None
ip       = "c-crime-0.itsec.cs.upb.de"
port     = 10004
username = "nleerman"

PAYLOAD_PREFIX  = "Cookie: flag="
MIN_CHAR_VAL    = 0
CHAR_LIST       = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '
MAX_CHAR_VAL    = len(CHAR_LIST)-1
K               = 13 # Max len of payload

def get_char_val(i : int) -> str:
    if i < MIN_CHAR_VAL or i > MAX_CHAR_VAL:
        raise Exception(f"WHO TRIED TO GET THE CHAR OF {i} >:(")
    return chr(i)

def get_char_val(i):
    return CHAR_LIST[i]

def get_ciphertext(text : str) -> str:
    # Choosing option 1) Encrypt
    conn.send_message(b'1')

    # Sending the payload (text)
    conn.send_message(bytes(text, "utf-8"))

    # Sending username and storing the answer
    conn.send_message(bytes(username, "utf-8"))

    messages = conn.get_messages()

    return messages[-5]

def CRIME():

    print("Starting an evil CRIME...")

    flag = "ITS{"
    i = MIN_CHAR_VAL
    char = None

    print(flag)
    #while i <= MAX_CHAR_VAL:
    while char != '}' and i <= MAX_CHAR_VAL:
        char_found = False
        payload = PAYLOAD_PREFIX + flag + get_char_val(i)
        if len(payload) > K:
            payload = payload[-K:]
        cipher = get_ciphertext(payload)
        l = len(cipher)
        i += 1
        while i <= MAX_CHAR_VAL and not char_found:
            payload = PAYLOAD_PREFIX + flag + get_char_val(i)
            if len(payload) > K:
                payload = payload[-K:]
            cipher = get_ciphertext(payload)
            cipherlen = len(cipher)
            if cipherlen > l:
                if i == 1:
                    char_found = True
                    char = get_char_val(0)
                    flag += char
                    print(repr(flag))#, end="\r")
                    i = MIN_CHAR_VAL
                else:
                    raise Exception("Cipher is longer than before and was not detected shorter before.")
            elif cipherlen < l:
                char_found = True
                char = get_char_val(i)
                flag += char
                print(repr(flag))#, end="\r")
                i = MIN_CHAR_VAL
            else:
                i += 1
    return flag

def do_it():

    # Establish connection
    global conn
    conn = util.ctf_connection()
    ##conn.set_autoprint(True)
    conn.connect(ip, port)

    # Get the flag
    cookie = CRIME()
    print("Did we find the cookie?")
    print("Cookie:")
    print(cookie)

    # Leave
    conn.close()

if __name__ == "__main__":

    do_it()
    sys.exit()

    # -----------------
    #       TEST
    # -----------------

    # <Testing get_char_val()
    for i in range(MIN_CHAR_VAL, MAX_CHAR_VAL + 1):
        print(get_char_val(i), end = ", ")
    print()
    # >

    # <Testing get_ciphertext()
    cipher1 = cipher2 = b''
    try:
        conn = util.ctf_connection()
        conn.connect(ip, port)

        cipher1 = get_ciphertext("Foo")
        cipher2 = get_ciphertext("Bar")
    finally:
        conn.close()

    assert(len(cipher1) == len(cipher2))
    
    print(cipher1)
    print(cipher2)
    print("get_ciphertext: Test positive.")
    # >