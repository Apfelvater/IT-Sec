# nc c-rsa_lsb-0.itsec.cs.upb.de 10003
# ------------------------------------
#         LSB-OracleAttack.py
# ------------------------------------
#
# This script calculates the message of a given ciphertext; given an Oracle, that tells you for any ciphertext if the message is odd or even

def ask_LSB_oracle(cipher):
    # TODO: send cipher to server and see what he does... ;)
    return 0


def LSB_oracle_attack(cipher, enc_exp, modulus):
    interval = list(range(modulus))
    i = 1
    while(len(interval) > 1):
        mult = 2 ** i
        new_cipher = (mult**enc_exp % modulus) * cipher # here % N ??
        if ask_LSB_oracle(new_cipher) == 1:             # 2*m % N is odd
            interval = interval[len(interval)//2 +1:]
        else:                                           # 2*m % N is even
            interval = interval[:len(interval)//2 +1]
        i += 1
    return interval[0]