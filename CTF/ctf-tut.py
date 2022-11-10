from pwn import *
from library.util_classes import last_3

############ GLOBAL ###############
conn = remote("c-how-to-tcp-0.itsec.cs.upb.de", 10000)
last_3_lines = last_3()
###################################

def read_until(terminator : str):
    response = b''
    conn.send(b'')
    while bytes(terminator, "utf-8") != response.strip():
        try:
            response = conn.recvline()
            print(response)
            last_3_lines.add(response)
        except EOFError:
            print("Line", terminator, "was not received.")
            return

def read_welcome():
    welcome_str = "###END WELCOME###"
    read_until(welcome_str)

def read_richtig():
    richtig_str = "Richtig!"
    read_until(richtig_str)

def read_order():
    order_str = "Bitte gib die Summe der obigen 2 Zahlen ein"
    read_until(order_str)


def main():
    print("Looking for welcome...")
    read_welcome()

    solve_count = 0
    while (solve_count < 200):
        read_order()
        a = int(last_3_lines.get(2))
        b = int(last_3_lines.get(1))
        print("Answering", a+b, "...")
        conn.sendline(b'%i'%(a+b))
        solve_count += 1
    
    response = conn.recvline()
    while (response != ''):
        try:
            print(response)
            response = conn.recvline()
        except EOFError:
            response = ''

if __name__ == "__main__":
    main()