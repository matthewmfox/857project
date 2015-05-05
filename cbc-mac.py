import imp
imp.load_source('pyaes', './pyaes/pyaes/aes.py')
import pyaes

###UFE Regular
import random
class UFE:
    def __init__(self, modeOfOperation):
        self.modeOfOperation = modeOfOperation
        # self.k1 = key1
        # self.k2 = key2
        # self.k3 = key3
        # self.modifiedUFE = modifiedUFE
        # self.m2rRatio = m2rRatio
        # self.blockSize = 16
    def encrypt(self, message):
        # create random r
        r = 0
        # encrypt message and create ciphertext
        if self.modeOfOperation == "CTR":
            counter = pyaes.Counter(initial_value = r)
            aes = pyaes.AESModeOfOperationCTR(self.k1, counter = counter)
            ciphertext = aes.encrypt(message)
        
        
        # CBC Mode of Operation
        elif self.modeOfOperation == "CBC":
            (paddedMessageBlocks, numBlocks) = self.pad_message_CBC(message)
            ciphertext = ''
            aes = pyaes.AESModeOfOperationCBC(self.k1, iv = r)
            for i in range(numBlocks):
                ciphertext = ciphertext + aes.encrypt(paddedMessageBlocks[i])
            
            
            
        # CFB Mode of Operation
        elif self.modeOfOperation == "CFB":
            aes = pyaes.AESModeOfOperationCFB(self.k1, iv = r)
            ciphertext = aes.encrypt(message)
            
        # create CBC-MAC of ciphertext
        CBC_MAC = self.cbc_mac(self, message)
        
        return (ciphertext, CBC_MAC)


    def decrypt(self, ciphertext):
        pass


    def small_erection(self, message):
        # Eugene get this shit done
        # Can't be bigger than 16 bits 
        pass
    
    def pad_message_CBC(self, message):
        # TODO
        # pad message so that it is a multiple of 16 bytes
        # returns a list of plaintexts in 16 byte blocks and the number of blocks
        pass
    
    def cbc_mac(self, message):
        aes1 = pyaes.AES(self.k2)
        aes2 = pyaes.AES(self.k3)
        # convert message to bytes
        message_bytes = [ ord(c) for c in message ]
        #ciphertext = aes.encrypt(plaintext_bytes)
        n = len(message)
        i=0
        last=0
        while i<n-1:
            nxt=aes1.encrypt(chr(last)^message_bytes[i])
            i+=1
            last=nxt
        nxt=aes2.encrypt(chr(last)^message_bytes[n-1])
        # convert bytes back to string
        nxt = "".join(map(chr, nxt))
        return nxt
        
        
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

    def bits_to_int(self, bits):
        e = 0
        res = 0
        for i in reversed(range(len(bits))):
            if bits[i] == 1:
                res = res + (2**e)
            e = e + 1
        return res

#def ufe(r,k1,k2,k3,message,encrypt):
#    p=ctr(r,len(message),k1,encrypt)
#    cipher=[]
#    for i in message:
#        cipher[i]=message[i]^p[i]
#    X=cbc_mac(cipher,encrypt,k2,k3)
#    sigma=r^X
#    return cipher,sigma
#
#def ctr(r,n,k1,encrypt):
#    i=0
#    p=[]
#    while i<n:
#        p[i]=encrypt(k1,r+i)
#        i+=1
#    return p
a = UFE('CTR')
print a.bits_to_int([1,1,0])

