from pwn import *

class last_3(object):
    '''Cyclic object to store the last 3 added values of any type.
    add(val) adds val at front position.
    get(index) returns the value at front position minus index. e.g. get(1) returns value added previous to the last value.'''
    def __init__(self):
        self.lines = [None, None, None]
        self.last = -1

    def _next_i_(self):
        self.last = (self.last + 1) % 3

    def add(self, val):
        self._next_i_()
        self.lines[self.last] = val

    def get(self, index = 0):
        if index > 2 or index < 0:
            raise Exception("This class only saves last 3 entries (index 0-2)")
        i = (self.last - index) % 3
        return self.lines[i]

class last_n(object):
    '''Cyclic object to store the last n added values of any type.
    '''
    def __init__(self, n):
        self.n = n
        self.lines = [None] * n
        self.last = -1

    def _next_i_(self) -> int:
        """returns the next index to the newest value"""
        self.last = (self.last + 1) % self.n

    def add(self, val):
        """add(val) adds val at front(=last) position."""
        self._next_i_()
        self.lines[self.last] = val

    def get(self, index = 0):
        """get(index) returns the value at front position minus index. \n
        e.g. get(1) returns value added previous to the last value.\n
        Returns None if value at index not found."""
        if index > self.n-1 or index < 0:
            return None
        i = (self.last - index) % self.n
        return self.lines[i]

    def get_last_n(self, n):
        """get_last_n(n) returns a list of the last n added values. result[n] is the most recent added value.\n
        Returns None if requested more values than in storage."""
        if n > self.n:
            return None
        r = self.last + 1
        if n < r:
            return self.lines[r - n : r]
        else:
            return self.lines[r - n :] + self.lines[: r]


class ctf_connection(object):
    
    def __init__(self, n = 16) -> None:
        self.connection = None
        self.msg_buf_len = n
        self._message_ring = last_n(n)
        self.autoprint = False
        self._line_of_interest = ""
        self._save_next = False

    def _store_line(self, line: str):
        self._message_ring.add(line)
        if self._save_next:
            self._line_of_interest = line
            self._save_next = False

    def _read_until(self, delim = b'>'):
        data = self.connection.recvuntil(delim)
        if b'\n' in data:
            data = data.split(b'\n')[:-1]
            #if not self.autoprint:
            #    print(f"Received {len(data)} lines.")
            for line in data:
                self._store_line(line)
                if self.autoprint:
                    print(line)

    def _read_messages(self):
        if not self.connection:
            return -1
        line = self.connection.recvline()
        m_count = 0
        while (line and line != b''):
            m_count += 1
            self._store_line(line)
            line = self.connection.recvline()
            if self.autoprint:
                print(line)
        #if not self.autoprint:
        #    print(f"Received {m_count} messages.")

    def set_autoprint(self, auto = None):
        '''Tells the object to automatically print any line, that it receives from the connection.'''
        if auto == None:
            self.autoprint = not self.autoprint
        else:
            self.autoprint = auto

    def connect(self, ip: str, port: int):
        self.connection = remote(ip, port)
        print("Connection established.")
        self.connection.send(b'')
        self._read_until(b'>')
        
    def print_messages(self):
        '''prints the last (n) received messages.'''
        if not self.connection:
            print("use 'connect(ip, port)' first!")
        msg = self._message_ring.get(0)
        i = 1
        while (msg):
            print(f"{i}| {msg.strip()}")
            msg = self._message_ring.get(i)
            i += 1

    def just_send_this(self, x : bytes):
        self.connection.send(x)
        if x.split(b'\n')[-1].strip() == b'':
            # last symbol is not a newline
            self.connection.send(b'\n')

    def send_message(self, message : bytes):
        self.connection.sendline(message)
        self._read_until(b'>')

    def send_all(self, messages : list[bytes]):
        for m in messages:
            self.send_message(m)
    
    def close(self):
        self.connection.close()
        self._message_ring = last_n(self.msg_buf_len)

    def set_save_next(self, save = None):
        '''Tells the ctf-connection to store the next received line.'''
        if save == None:
            self._save_next = not self._save_next
        else:
            self._save_next = save

    def get_line_of_interest(self) -> str:
        '''Returns the line, that was specially stored.\n
        If set_save_next() was not called before a line was sent from server, None will be returned.\n'''
        return self._line_of_interest
        
# ------------- Testing -------------

if __name__ == "__main__":
    # #  #  #  # #
    # TEST CASES #
    #  # #  # #  #
    nobj = last_n(6)
    assert(nobj.lines == [None] * 6)

    for i in range(10):
        nobj.add(i)
    assert(nobj.lines == [6,7,8,9,4,5])

    l = []
    for i in range(6):
        l.append(nobj.get(i))
    assert(l == [9, 8, 7, 6, 5, 4])

    assert(nobj.get_last_n(3) == [7,8,9])
    
    for i in range(10,13):
        nobj.add(i)
    assert(nobj.get_last_n(5) == [8,9,10,11,12])

    print("Tiny Unit Test of last_n class done.")
