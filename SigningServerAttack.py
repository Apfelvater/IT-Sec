# SigningServerAttack.py
d = 7727

class test_signing_server(object):
    def __init__(self, d, n):
        self.d = d
        self.n = n

    def sign(self, m):
        return m ** self.d % self.n

def encrypt(m,e,n):
    return m**e % n

def attack(m, e, n, server):
    m_evil = 2 * m % n
    s = server.sign(m_evil)
    i = 1
    t = 2 
    while (encrypt(s // t, e, n) != m) & (i < n):
        if i == d:
            raise Exception(f"s = {s}, t = {t}\
                s' = {s//t}\nm'={encrypt(s // t, e, n)}")
        t = (t << 1) % n
        i += 1
    return s, i


if __name__ == "__main__":  
    n = 19757939
    e, d = 2557, 7727

    signer = test_signing_server(d, n)

    m_str = "F!"
    m_bytes = m_str.encode("ascii")
    m_int = int.from_bytes(m_bytes, "big")

    print(m_int)

    print(attack(m_int, e, n, signer))

