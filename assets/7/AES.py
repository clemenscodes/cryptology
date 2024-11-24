class AES:

    def __init__(self, key, IV):
        self.sbox = [None for x in range(256)]
        self.sboxInv = [None for x in range(256)]
        self.mult09 = [None for x in range(256)]
        self.mult0B = [None for x in range(256)]
        self.mult0D = [None for x in range(256)]
        self.mult0E = [None for x in range(256)]
        self.IV = IV
        self.readTables()
        self.Rcon = ["0", "01000000", "02000000", "04000000", "08000000", "10000000", "20000000", "40000000", "80000000", "1B000000", "36000000"]
        self.Rkey = self.expandKey(key)

    def readTables(self):
        f = open("./tables.txt", "r")
        tables = f.read().replace("\t", "").splitlines()[2:]
        for i in range(256):
            self.sbox[i] = tables[i][2:4]
            self.sboxInv[i] = tables[i][4:6]
            self.mult09[i] = tables[i][10:12]
            self.mult0B[i] = tables[i][12:14]
            self.mult0D[i] = tables[i][14:16]
            self.mult0E[i] = tables[i][16:18]

    def expandKey(self, key):
        Rkey = [None for x in range(11)]
        Rkey[0] = key
        for i in range(1, len(Rkey)):
            w0 = Rkey[i-1][0:8]
            w1 = Rkey[i-1][8:16]
            w2 = Rkey[i-1][16:24]
            w3 = Rkey[i-1][24:32]
            Rw0 = self.xor(w0, self.xor(self.subByte(self.rot(w3, 2, 8), 4), self.Rcon[i], 8), 8)
            Rw1 = self.xor(w1, Rw0, 8)  
            Rw2 = self.xor(w2, Rw1, 8)
            Rw3 = self.xor(w3, Rw2, 8)
            Rkey[i] = Rw0 + Rw1 + Rw2 + Rw3
        return Rkey

    def padInv(self, plain):
        l = len(plain)
        pad = int(plain[l-2:l], 16)
        for i in range(pad):
            cur = int(plain[l-2-i*2:l-i*2], 16)
            if cur != pad:
                return plain
        return plain[0:l-pad*2]

    def rot(self, string, n, w):
        n = n % w
        return string[(n):] + string[:(n)]

    def xor(self, text1, text2, length):
        enc = int(text1, 16) ^ int(text2, 16)
        return format(enc, "x").zfill(length)

    def subByte(self, bytes, length):
        res = ""
        for i in range(length):
            res += self.sbox[int(bytes[i*2:i*2+2], 16)]
        return res

    def subByteInv(self, bytes, length):
        res = ""
        for i in range(length):
            res += self.sboxInv[int(bytes[i*2:i*2+2], 16)]
        return res

    def shiftRowsInv(self, bytes):

        return shifted

    def mixColumnsInv(self, bytes):

        return mixed

    def decryptBlock(self, block):

        return block
            
    def decrypt(self, cipher):

        return plain
