###UFE Regular
import random
class UFE:
    def __init__(self, modeOfOperation, key1, key2, key3, modifiedUFE=False, m2rRatio=1):
        self.modeOfOperation = modeOfOperation
        self.k1 = key1
        self.k2 = key2
        self.k3 = key3
        self.modifiedUFE = modifiedUFE
        self.m2rRatio = m2rRatio
        self.blockSize = 16
    def encrypt(self, message):
        pass

    def decrypt(self, ciphertext):
        pass

    # returns a list, first element is r without padding represented as list of bits
    # second element is r with padding represented as list of bits
    def eugenes_large_erection(self, message):
        # Eugene get this shit done
        result = []
        messageBitArray = self.string_to_bits(message)
        lengthOfR = len(messageBitArray)/self.m2rRatio
        rand = random.getrandbits(lengthOfR)
        rand = self.int_to_bitlist(rand)
        result.append(rand)
        while len(rand) < self.blockSize:
            rand.append(0)
        result.append(rand)
        return result

    # returns a list of bits
    def string_to_bits(self, s):
        result = []
        for c in s:
            bits = bin(ord(c))[2:]
            bits = '00000000'[len(bits):] + bits
            result.extend([int(b) for b in bits])
        return result

    # input is a list of bits
    def bits_to_string(self, bits):
        chars = []
        for b in range(len(bits) / 8):
            byte = bits[b*8:(b+1)*8]
            chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
        return ''.join(chars)

    # converts an integer into a list of bits
    def int_to_bitlist(self, n):
        return [int(digit) for digit in bin(n)[2:]]

def cbc_mac(cipher,encrypt,k2,k3):
    n = len(cipher)
    i=0
    last=0
    while i<n-1:
        nxt=encrypt(k2,last^cipher[i])
        i+=1
        last=nxt
    nxt=encrypt(k3,last^cipher[n-1])
    return nxt

def ufe(r,k1,k2,k3,message,encrypt):
    p=ctr(r,len(message),k1,encrypt)
    cipher=[]
    for i in message:
        cipher[i]=message[i]^p[i]
    X=cbc_mac(cipher,encrypt,k2,k3)
    sigma=r^X
    return cipher,sigma

def ctr(r,n,k1,encrypt):
    i=0
    p=[]
    while i<n:
        p[i]=encrypt(k1,r+i)
        i+=1
    return p


