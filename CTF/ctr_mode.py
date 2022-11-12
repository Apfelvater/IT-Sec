import sys
import os

def xor_encrypt(var, key, byteorder=sys.byteorder):
    key, var = key[:len(var)], var[:len(key)]
    int_var = int.from_bytes(var, byteorder)
    int_key = int.from_bytes(key, byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), byteorder)

MY_CIPHER = b"8f5689ed869845cbe1beb9fdb2dceb1e807caeb9939864ebc68bf5e2ff9ec861b871f3a9ccb507cac68be4e1dd8a837abc29fd80c6c264f3d98fb9f9b2ddc63c9022ecf689ed6feadb\
9ae3f7bca18f7abd6bfdb5918e52a981d5b6beead7d026e623f4edeedd6ef4dac1a4fcadddd625f822fd8bc0ca68f9da96b9faaec3d619c252beaeccc879a5959af3b4e8c28e60a57ff1acd9c861f6d\
68fe2a5f383c96ca067b0a182c060f3998fe6bcf0848575bc7ab2a386c060f38e9fabfcb2d4ca3ee739e6bc948823a7b8e4d7afff889660e55fbca3cecd6cf8d0d4b6a9f2c0b347e476b3f6d8853db1\
80e39c8dff8e8364bc3e98a3cad769f6db89acecfb978f64e433b9a8cfd46cebd0c2b6aeeee0ec57a77db3a8cacc64f0dbd4b6a7f9889639a97fb4bbccb507dcda81fda5f9d7c672a472baf0e0ec5ee\
4ecdee393ffd9884bab7ca8a39ee73df1ea83a593f0dc8d71972382b7ccca62c085b1a5aaf988d022fd21a0"

'''
nonce = os.urandom(16)
_key = os.urandom(32)
counter=lambda: nonce
print(nonce)
print("---")
print("Bin::{0:b}::!".format(int.from_bytes(nonce, "big")))
print("---")
print("Hex::{0:x}::!".format(int.from_bytes(nonce, "big")))
print("---")'''

def byte_length(i):
    return (i.bit_length() + 7) // 8

plainInt = int.from_bytes(bytes("""""", "utf-8"), sys.byteorder)
print("Int:{0}\nHex:{0:x}".format(plainInt))

length = byte_length(plainInt)
cipherPartInt = int.from_bytes(MY_CIPHER[:length], "big")

print("{0:x} XOR {1}".format(plainInt, cipherPartInt))
encOfNonceCtr = plainInt ^ cipherPartInt
print("= {0:x}".format(encOfNonceCtr))

#TODO: xor ALL

#TODO: Line Seperators
"""
GET / HTTP/1.1
Host: itsec.cs.upb.de
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: flag=**FLAG_REDACTED**"""