import sys

def byte_xor_int(bvalue, ivalue, byteorder=sys.byteorder):
    if len(bvalue) != len("%i"%ivalue):
        raise ValueError("ERROR: Lengths of parameter values differ!")
    int_bvalue = int.from_bytes(bvalue, byteorder)
    int_enc = int_bvalue ^ ivalue
    return int_enc.to_bytes(len(bvalue), byteorder)

def bitwise_xor_bytes(value1, value2, byteorder=sys.byteorder):
    if len(value1) != len(value2):
        raise ValueError("ERROR: Lengths of parameter values differ!")
    int_value1 = int.from_bytes(value1, byteorder)
    int_value2 = int.from_bytes(value2, byteorder)
    int_enc = int_value1 ^ int_value2
    return int_enc.to_bytes(len(value1), byteorder)

def int_to_base(n, b):
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits[::-1]

def str_to_mz(m, mi):
    for xi in m:
        mi = mi ^ ord(xi)
    return mi


# Aufgabe 2b

MAC = 0b01101100
m0  = 0b11111111
m   = "FILMABEND?"
mz = str_to_mz(m, m0)
k = (MAC - mz) % 256
str_k = "{0:b}".format(k)
print("k =", str_k)


# Aufgabe 2c
print("m_z = {0:b}".format(mz))

answers = \
"""DUNE
BATMAN
LOTR
TENET
STARWARS
MATRIX""".split("\n")

for ans in answers:
    mz = str_to_mz(ans, m0)
    MAC = (mz + k) % 256
    if MAC == 0b11010100:
        print(f"THEY'RE WATCHING {ans} WITHOUT ME!! >:(")
        raise Exception("grrr")

#ints = [int.from_bytes(s.encode("ascii"), "big") for s in answers]
#print(ints)
