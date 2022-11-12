import os
import sys

from library.util_classes import ctf_connection

conn = None

# ---------- Networking functions ----------
# nc c-poa-0.itsec.cs.upb.de 10002
def ask_padding_oracle(cipher : bytes):

    #print("Checking padding of cipher", cipher)

    # Choosing "2) Check if a message is corr..."
    conn.send_message(b'2')

    conn.set_save_next(True)
    # Sending the actual cipher message to check against
    conn.send_message(cipher)

    # Check if next output is "Valid Ciphertext :)" or "Invalid Ciphertext :("
    answer = conn.get_line_of_interest()
    #print(answer)
    if b':)' in answer:
        return True
    elif b':(' in answer:
        return False
    else:
        #print(f"Cant find the smiley in server's answer '{answer}'")
        return None

# Test-Tautology
#def ask_padding_oracle(cipher : bytes):
#    print(cipher)
#    return True

def receive_ciphertext():

    conn.set_save_next(True)
    # Choosing "1)"
    conn.send_message(b'1')

    return conn.get_line_of_interest()


# ------------------------------------------

def get_message_from_x(x, iv):

    x_ints = [int.from_bytes(x[i], "big") for i in range(len(x))]
    iv_ints = [int(iv[i:i+2], 16) for i in range(0, len(iv), 2)]
    m_int = [x_ints[i] ^ iv_ints[i] for i in range(len(x_ints))]
    
    return "".join([chr(i) for i in m_int])

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
    def test_a():
        s = "aabcdd4269f0"
        print("Teststring:",s)
        print("as bytes array:\n", byte_str_2_byte_arr(s).hex())
        print()
        print("01 XOR ff =")
        print(get_x_byte(b'\xff'))
    def test_b():
        ask_padding_oracle(b'9937989a7a4291f688f625496f601a16f5bd93606e01bdde5669e02fa1d19412f3a7a8d7607e91da7f1d838bccfa5091eea8df282bdce3de1760c5b69bc80fa8')
    def test_c():
        x   = [b"\xd0", b"\x63", b"\xcb", b"\xe1", b"\x2e", b"\x30", b"\xe4", b"\xc3", b"\xbf", b"\xa9", b"\x51", b"\x21", b"\x5c", b"\x3f", b"\x55", b"\x64"]
        iv  = b"9937989a7a4291f688f625496f601a16"
        print(get_message_from_x(x, iv))
    test_c()


BLOCK_SIZE = 16 #Bytes
# IV to get padding
test_IV = bytearray(os.urandom(BLOCK_SIZE))
R_bytes = bytearray(b'')

def main():

    conn.set_autoprint(False)

    cipher = "9937989a7a4291f688f625496f601a16f5bd93606e01bdde5669e02fa1d19412f3a7a8d7607e91da7f1d838bccfa5091eea8df282bdce3de1760c5b69bc80fa8"
    bytes_in_cipher = len(cipher)//2

    cipher_blocks = [cipher[i*2*BLOCK_SIZE:(i+1)*2*BLOCK_SIZE] for i in range(bytes_in_cipher // BLOCK_SIZE)]

    # i assume, that it is...
    orig_IV = cipher_blocks[0]
    # which would mean, that
    cipher_blocks = cipher_blocks[1:]
    # X = Enc(C, key)
    X = [None] * BLOCK_SIZE

    print("Cipher split into Blocks:")
    print(cipher_blocks)

    def calc_R_bytes(pad_val : int):
        #IV[i] = X[i] XOR pad_val (padding value 0x01, 0x02, ...)
        R = bytearray()
        for x in [x for x in X if x != None]:
            x_int = int.from_bytes(x, "big")
            R.append(x_int ^ int.from_bytes(pad_val, "big"))
        return R

    def get_next_L(old_IV, old_i):
        l = len(old_IV) - old_i - 1  # length of unmodified left part of IV
        return old_IV[:l+1]
    
    def calculate_x(index):
        global test_IV, R_bytes
        pad_val = index.to_bytes(1, 'big')
        print(f"Calculating x for padding of length {index} and padding values {pad_val}")
        
        # byte no. index
        IV_byte_gen = zero_to_n(255)
        # IV parts
        L = get_next_L(test_IV, index)
        R_bytes = calc_R_bytes(pad_val)
        padding_correct = False
        oracle_count = 0
        while not padding_correct:
            try:
                M = next(IV_byte_gen)
            except:
                conn.close()
                raise Exception("Tried 255 different bytes. No positive outcome.")
            if ((oracle_count * 100 / 255) % 2.55) == 0.0:
                print(u"\u2588", end="")
            test_IV = L + M + R_bytes
            payload = (test_IV + test_cipher).hex()
            padding_correct = ask_padding_oracle(bytes(payload, "utf-8"))
            oracle_count += 1
        print()
        #print(f"Attempt no.{oracle_count}: Payload IV'+C = {payload} has correct padding.")
        print("---")

        X[BLOCK_SIZE-index] = get_x_byte(M, pad_val)
        print(f"Got X[{BLOCK_SIZE-index}] = {X[BLOCK_SIZE-index]}")
        print("---")
        
    def calc_all_x():
        for i in range(1, BLOCK_SIZE+1):
            calculate_x(i)

    m = ["d063cbe12e30e4c3bfa951215c3f5564"]
    for c_blocc in cipher_blocks[1:]:
        X = [None] * BLOCK_SIZE

        # This part is only made for the first B L O C C
        test_cipher = bytes(byte_str_2_byte_arr(c_blocc))

        calc_all_x()
        print("X =", [x.hex() for x in X])

        m.append(get_message_from_x(X, orig_IV))

    message_string = "".join(m)

    print((len(message_string)//4-2) * '~' + "Done" + (len(message_string)//4-2) * '~')
    print(message_string)
    print(len(message_string)//2 * '~')
        

if __name__ == "__main__":
    IP = "c-poa-0.itsec.cs.upb.de"
    PORT = 10002
    conn = ctf_connection()
    conn.set_autoprint()
    conn.connect(IP, PORT)
    
    main()
    '''
    if len(sys.argv) < 2:
        print("Starting test procedure...")
        test()
    else:
        print("Starting main procedure...")
        main()
    '''

    print("Done. Closing connection...")
    conn.close()