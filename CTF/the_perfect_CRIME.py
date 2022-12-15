# CRIME Attack:

PAYLOAD_PREFIX  = "flag="
MIN_CHAR_VAL    = 48        # chr(48) = "0"
MAX_CHAR_VAL    = 109       # get_char_val(MAX_CHAR_VAL) returns z

def get_char_val(i : int) -> str:
    if i < MIN_CHAR_VAL or i > MAX_CHAR_VAL:
        raise Exception(f"WHO TRIED TO GET THE CHAR OF {i} >:(")
    if i > 48 + 9:
        i += 7
    if i > 90:
        i += 6
    return chr(i)

def get_ciphertext(text : str, username : str) -> str:
    raise NotImplementedError()

def CRIME(username):
    payload = PAYLOAD_PREFIX
    i = 0
    while i < MAX_CHAR_VAL:
        char_found = False
        cipher = get_ciphertext(payload + get_char_val(i))
        l = len(cipher)
        i += 1
        while i < MAX_CHAR_VAL and not char_found:
            cipher = get_ciphertext(payload + get_char_val(i))
            if len(cipher) > l:
                if i == 1:
                    print("Seems like the char was char(0)")
                    char_found = True
                    payload += get_char_val(0)
                    i = 0
                else:
                    raise Exception("Cipher is longer than before and was not detected shorter before.")
            elif len(cipher) < l:
                char_found = True
                payload += get_char_val(i)
                i = 0
            else:
                i += 1
    return payload

def do_it():
    cookie = CRIME("nleerman")
    print("Did we find the cookie?")
    print("Cookie:")
    print(cookie)

if __name__ == "__main__":
    # -----------------
    #       TEST
    # -----------------

    # Testing get_char_val()
    for i in range(48, MAX_CHAR_VAL + 1):
        print(get_char_val(i), end = ", ")