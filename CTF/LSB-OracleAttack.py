# nc c-rsa_lsb-0.itsec.cs.upb.de 10003
# ------------------------------------
#         LSB-OracleAttack.py
# ------------------------------------
#
# This script calculates the message of a given ciphertext; given an Oracle, that tells you for any ciphertext if the message is odd or even


import os
import sys
import time
import math
from library.util_classes import ctf_connection

conn = None
username = "nleerman"
logfile_path = "./LSB_OA_.LOG.txt"

class progress(object):

    def __init__(self, n, reverse_max = False):
        self.max = n
        self.reverse_max = reverse_max
        self.log_max = math.log(n, 2)
        self.print_len = 100

    def print_progress(self, prog):
        self.rel_percent = math.log(prog, 2) / self.log_max
        self.abs_percent = self.print_len / prog
        print((7 + self.print_len) * " ", end = "\r")
        round_percent = math.ceil(self.rel_percent * 10 * self.print_len) / (10 * self.print_len)
        barlen = (1- round_percent) * self.print_len if self.reverse_max else round_percent * self.print_len
        print(f"{round_percent * 100:.1f}% [" + "=" * int(barlen) + "]", end = "\r")

    def done(self):
        print((7 + self.print_len) * " ", end = "\r")
        if self.reverse_max:
            print("100% =")
        else:
            print("100% [" + self.print_len * "=" + "]")

def open_logfile(path):
    i = 0
    path_parts = path.split(".LOG.")
    path = ".LOG.".join((path_parts[0] + str(i), path_parts[1]))
    while os.path.exists(path):
        i += 1
        path = ".LOG.".join((path_parts[0] + str(i), path_parts[1]))
    return open(path, "w")

def write_to_log(fd, n, l, r, t):
    lo = str(n*(l/t))
    hi = str(n*(r/t))
    line = f"Interval from: {l}\nto: {r}\ndiv by t:{t}\n::Interval=[{lo}..{hi}\n---\n"
    fd.write(line)

def decrypt(cipher,d,n):
    return cipher**d % n

def encrypt(message,e,n):
    return message**e % n

def ask_LSB_oracle(cipher):
    answer_str = "Have a bit: m&1="

    # Choosing Option 3 "Oracle"
    conn.send_message(b'3')

    conn.set_save_next(True)
    # Sending the "payload"-cipher
    conn.send_message(bytes(str(cipher), "utf-8"))

    answer = conn.get_line_of_interest().decode("utf-8")
    # answer=Have a bit: m&1=0
    if not answer_str in answer:
        raise Exception("Oracle did not answer as expected. Answer was:\n" + answer)
    else:
        LSB = int(answer.strip("\n\r ")[-1])
    return LSB

def get_public_key() -> tuple:
    N, e = "-1", "-1"

    # Choosing Option 1 "Get Public Key"
    conn.send_message(b'1')

    # Searching for N=... and e=... in answers
    answers = [b.decode("utf-8").strip("\n\r ") for b in conn.get_messages()]
    for ans in answers:
        if ans[:2] == "N=":
            N = ans[2:]
        elif ans[:2] == "e=":
            e = ans[2:]
    
    return int(N), int(e)

def get_ciphertext():

    # Choosing Option 2 "Get Ciphertext"
    conn.send_message(b'2')

    # Sending username
    conn.send_message(str.encode(username, "utf-8"))

    # Searching for c=... in answers
    answers = [b.decode("utf-8").strip("\n\r ") for b in conn.get_messages()]
    for ans in answers:
        if ans[:2] == "c=":
            return int(ans[2:].strip("\n\r "))
    raise Exception("Ciphertext not found in messages.")

def LSB_oracle_attack(cipher: int, enc_exp: int, modulus: int) -> int:
    t = 2
    last_l = 0
    prog = progress(modulus)
    while(modulus > t):
        c_send = (t ** enc_exp * cipher) % modulus
        LSB = ask_LSB_oracle(c_send)
        l = 2 * last_l + LSB
        r = l + 1
        last_l = l
        write_to_log(logfile, modulus, l, r, t)
        prog.print_progress(t)
        t = 2 * t
    prog.done()
    # undoing the last t multiplication for further use of t
    t = t // 2
    top = (r * modulus) // t
    f_top = modulus/t * r
    if f_top - top == 0:
        print("We might have a floating problem. Please check for rounding:")
        print(f"r/t = \n{r}\n/\n{t}\n=\n{f_top}")
    return top

def decode_int(m_int):
    try:
        return m_int.to_bytes(int((m_int.bit_length() + 7)/8), "big").decode("ascii")
    except:
        print("Decoding failed.")
        return (m_int, m_int.to_bytes(int((m_int.bit_length() + 7)/8), "big"))

if __name__ == "__main__":
    global logfile
    logfile = open_logfile(logfile_path)

    print("Starting LSB-OracleAttack...")

    IP = "c-rsa_lsb-0.itsec.cs.upb.de"
    PORT = 10003
    conn = ctf_connection()
    conn.set_autoprint(False)
    conn.connect(IP, PORT)

    cipher = get_ciphertext()
    print("Cipher received.")
    logfile.write(f"Cipher = {cipher}\n")

    (N, e) = get_public_key()
    print("Public Key received.")
    logfile.write(f"P_k = ({N}, {e})\n")

    time_pre_attack = time.time()
    message = LSB_oracle_attack(cipher, e, N)
    print(f"Took {time.time() - time_pre_attack} seconds to find:")
    logfile.write(f"(int) Message = ({message})\n")

    message_str = decode_int(message)
    print(f"Message={message_str}")

    logfile.close()

def test():
    global logfile
    logfile = open_logfile(logfile_path)

    print("Starting Test...")

    p, q = 7727, 2557
    n = 19757939
    e, d = 13427, 473579
    m = 4616047
    c = encrypt(m, e, n)

    def ask_LSB_oracle(cipher):
        m = decrypt(cipher, d, n)
        return m%2

    m_int = LSB_oracle_attack(c, e, n)
    print(m_int)

    print(decode_int(m_int))

    print("Finished Test...")