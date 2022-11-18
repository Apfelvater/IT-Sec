# nc c-rsa_lsb-0.itsec.cs.upb.de 10003
# ------------------------------------
#         LSB-OracleAttack.py
# ------------------------------------
#
# This script calculates the message of a given ciphertext; given an Oracle, that tells you for any ciphertext if the message is odd or even

import os
from library.util_classes import ctf_connection

conn = None

"""
p, q = 7, 5
n = p * q
phi = (p-1)*(q-1)
e = 11
d = 11
p,q = 7727, 2557
n = p * q
phi = (p-1)*(q-1)
e = 13427
d = 473579
assert(e*d%phi == 1)
"""

def decrypt(cipher,d,n):
    return cipher**d % n

def encrypt(message,e,n):
    return message**e % n

def ask_LSB_oracle(cipher):

    # Choosing Option 3 "Oracle"
    conn.send_message(b'3')

    conn.set_save_next(True)
    # Sending the "payload"-cipher
    conn.send_message(cipher)

    answer = conn.get_line_of_interest()
    # TODO: Hier dann answer parsen zu LSB

    return 0

""" TESTING: PREDEFINED INPUT
print("------------------------")
print("----------TEST----------")
print("------------------------")
def ask_LSB_oracle(c):
    m = decrypt(c)
    print(f"The oracle answers to {c} with {m%2}")
    return m % 2 """
""" TESTING: PREDEFINED OUTPUT
odd = [1,1,0,0,0]
test_i = 0
def ask_LSB_oracle(c):
    global test_i
    print(f"{test_i}::Cipher is {c}")
    test_i += 1
    return odd[test_i-1]
"""
""" TESTING: RANDOM OUTPUT
def ask_LSB_oracle(c):
    r_i = 1 if (int.from_bytes(os.urandom(1), "big") > 127) else 0
    print(f"ask_oracle: cipher = {c}; random = {r_i}")
    return r_i
"""

def LSB_oracle_attack(cipher: int, enc_exp: int, modulus: int) -> int:
    t = 2
    last_l = 0
    last_r = 1
    while(modulus > t):
        c_send = (t ** enc_exp * cipher) % modulus
        print(f"t = {t}; e = {enc_exp}; c = {cipher}; N = {modulus}")
        print(f"c' = {c_send}")
        LSB = ask_LSB_oracle(c_send)
        l = 2 * last_l + LSB
        r = l + 1#2 * last_r - int(not LSB) # r == l + 1 ?
        print(f"interval=[{l},...,{r}]")
        last_l = l
        last_r = r
        t = 2 * t
    # undoing the last t multiplication for further use of t
    t = t/2
    top = (modulus * r)//t
    f_top = modulus*r/t
    if f_top - top == 0:
        print("We might have a floating problem. Please check for rounding:")
        print(f"r/t = {r}/{t} = {f_top}")
    return int(top)


if __name__ == "__main__":
    IP = "c-rsa_lsb-0.itsec.cs.upb.de"
    PORT = 10003
    conn = ctf_connection()
    conn.set_autoprint()
    conn.connect(IP, PORT)

    """TEST
    c = 5976034
    print(LSB_oracle_attack(c, e, n))
    """
