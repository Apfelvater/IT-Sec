import os
import sys

from library.util_classes import ctf_connection

conn = None

# ---------- Networking functions ----------
# nc c-poa-0.itsec.cs.upb.de 10002
def ask_padding_oracle(cipher : bytes):

    print("Checking padding of cipher", cipher)

    # Choosing "2) Check if a message is corr..."
    conn.send_message(b'2')

    conn.set_save_next(True)
    # Sending the actual cipher message to check against
    conn.send_message(cipher)

    # Check if next output is "Valid Ciphertext :)" or "Invalid Ciphertext :("
    answer = conn.get_line_of_interest()
    print(answer)
    if b':)' in answer:
        return True
    elif b':(' in answer:
        return False
    else:
        print(f"Cant find the smiley in server's answer '{answer}'")
        return None

def receive_ciphertext():
    pass

# ------------------------------------------

def byte_str_2_byte_arr(s):
    """Example: byte_str_2_byte_arr('ff1a') -> b'\xff\x1a'"""
    if len(s) % 2:
        raise Exception("Input string has to have even length!")
    return bytearray.fromhex(s)

def get_x_byte(IV_Byte, m_Byte=b'\x01'):
    if len(IV_Byte) != 1:
        raise Exception("Only give one byte of IV', please!")
    return (int.from_bytes(IV_Byte, "big") ^ int.from_bytes(m_Byte, "big")).to_bytes(1, "big")

def zero_to_n(n):
    '''Generator, that yields bytes from 0 to n.'''
    i = 0
    while i <= n: 
        yield i.to_bytes(1, "big")
        i += 1

def test():

    s = "aabcdd4269f0"
    print("Teststring:",s)
    print("as bytes array:\n", byte_str_2_byte_arr(s).hex())
    print()
    print("01 XOR ff =")
    print(get_x_byte(b'\xff'))
    ask_padding_oracle(b'9937989a7a4291f688f625496f601a16f5bd93606e01bdde5669e02fa1d19412f3a7a8d7607e91da7f1d838bccfa5091eea8df282bdce3de1760c5b69bc80fa8')
  
def main():
    conn.set_autoprint(False)

    cipher = "9937989a7a4291f688f625496f601a16f5bd93606e01bdde5669e02fa1d19412f3a7a8d7607e91da7f1d838bccfa5091eea8df282bdce3de1760c5b69bc80fa8"
    bytes_in_cipher = len(cipher)//2
    BLOCK_SIZE = 16 #Bytes

    cipher_blocks = [cipher[i*2*BLOCK_SIZE:(i+1)*2*BLOCK_SIZE] for i in range(bytes_in_cipher // BLOCK_SIZE)]

    # i assume, that it is...
    orig_IV = cipher_blocks[0]
    # which would mean, that
    cipher_blocks = cipher_blocks[1:]

    print("Cipher split into Blocks:")
    print(cipher_blocks)

    # Cipher used to get Padding from the oracle
    test_cipher = b''
    # Payload = IV'||C  ,C = test_cipher
    payload = b''
    # Beginning at last byte
    IV_index = BLOCK_SIZE - 1
    # X = Enc(C, key)
    X = [None] * BLOCK_SIZE
    #
    R_bytes = bytearray(b'')
    
    
    def calc_r_bytes(pad_val : int):
        #IV[i] = X[i] XOR pad_val (padding value 0x01, 0x02, ...)
        for x in [x for x in X if x != None]:
            x_int = int.from_bytes(x, "big")
            R_bytes.append(x_int ^ pad_val)
    
    def calculate_x(index):
        # param index: index of the important IV byte, that has to try all values 0-255
        # Length of the padding and value of each padding byte
        pad_len = BLOCK_SIZE - index
        pad_val = pad_len.to_bytes(1, "big")

        print(f"Calculating x for padding of length {pad_len} and padding values {pad_val}")
        
        # bytes 0 to index-1
        left_IV = bytearray(os.urandom(index))
        # byte no. index
        IV_byte_gen = zero_to_n(255)
        # bytes index+1 to n
        calc_r_bytes(pad_len)
        right_IV = R_bytes
        
        padding_correct = False
        oracle_count = 0
        while not padding_correct:
            try:
                iv_byte = next(IV_byte_gen)
            except:
                conn.close()
                raise Exception("Tried 255 different bytes. No positive outcome.")
            IV = left_IV + iv_byte + right_IV
            payload = (IV + test_cipher).hex()
            print(oracle_count, end=": ")
            padding_correct = ask_padding_oracle(bytes(payload, "utf-8"))
            oracle_count += 1
        print(f"Attempt no.{oracle_count}: Payload IV'+C = {payload} has correct padding.")
        print("---")

        X[index] = get_x_byte(iv_byte, pad_val)
        print(f"Got X[{index}] = {X[index]}")
        print("---")
        
    def calc_all_x():
        for i in range(BLOCK_SIZE-1, -1, -1):
            calculate_x(i)
            
    for c_blocc in cipher_blocks:
        # This part is only made for the first B L O C C
        test_cipher = bytes(byte_str_2_byte_arr(c_blocc))
        
        calc_all_x()
        print("X =", [x.hex() for x in X])
        
        # TOREMOVE:
        return
        

if __name__ == "__main__":
    IP = "c-poa-0.itsec.cs.upb.de"
    PORT = 10002
    conn = ctf_connection()
    conn.set_autoprint()
    conn.connect(IP, PORT)

    if len(sys.argv) < 2:
        print("Starting test procedure...")
        test()
    else:
        print("Starting main procedure...")
        main()

    print("Done. Closing connection...")
    conn.close()

'''
2228fcb3f6accf2d15c2a4c8a0df5766   f5bd93606e01bdde5669e02fa1d19412
b6952c942db6c1115acc051ba500665667 f5bd93606e01bdde5669e02fa1d19412
'''