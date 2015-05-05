import imp
imp.load_source('pyaes', './pyaes/pyaes/aes.py')
import pyaes
import math
import random
class UFE:
    def __init__(self, modeOfOperation, key1, key2, key3, modifiedUFE=False, m2rRatio=0.125):
        self.modeOfOperation = modeOfOperation
        self.k1 = key1
        self.k2 = key2
        self.k3 = key3
        self.modifiedUFE = modifiedUFE
        self.m2rRatio = m2rRatio
        self.blockSize = 16

    def encrypt(self, message):
        # create random r
        (r_padded, r_original) = self.eugenes_large_erection(message)
        # encrypt message and create ciphertext
        if self.modeOfOperation == "CTR":
            counter = pyaes.Counter(initial_value = self.bits_to_int(r_padded))
            aes = pyaes.AESModeOfOperationCTR(self.k1, counter = counter)
            ciphertext = aes.encrypt(message)
        
        
        # CBC Mode of Operation
        elif self.modeOfOperation == "CBC":
            (paddedMessageBlocks, numBlocks) = self.pad_message_CBC(message)
            ciphertext = ''
            aes = pyaes.AESModeOfOperationCBC(self.k1, iv = self.bits_to_string(r_padded))
            for i in range(numBlocks):
                ciphertext = ciphertext + aes.encrypt(paddedMessageBlocks[i])
            
            
            
        # CFB Mode of Operation
        elif self.modeOfOperation == "CFB":
            aes = pyaes.AESModeOfOperationCFB(self.k1, iv = self.bits_to_string(r_padded))
            ciphertext = aes.encrypt(message)
            
        # create CBC-MAC of ciphertext
        CBC_MAC = self.cbc_mac(ciphertext)
        
        
        # CBC_MAC is a list of bytes represented as integers
        # xor CMB_MAC with r
        r = self.bits_to_bytes(r_original)
        sigma = []
        for i in range(len(r)):
            sigma.append(CBC_MAC[i]^r[i])
            
        # sigma is a list of bytes represented as integers
        sigmaStr = ''
        for s in sigma:
            sigmaStr = sigmaStr + chr(s)
        return (ciphertext, sigma)
        


    def decrypt(self, ciphertext, sigma):
        
        # calculate CBC_MAC of ciphertext
        CBC_MAC = self.cbc_mac(ciphertext)
        
        # find r from sigma
        r = []
        for i in range(len(sigma)):
            r.append(chr(CBC_MAC[i]^sigma[i]))
        # turn r into eugene's form
        r_original = self.string_to_bits(r)
        # create r_padded
        # r_padded = self.pad(r_original)
        r_padded = []
        
        
        # decrypt using AES
        if self.modeOfOperation == "CTR":
            counter = pyaes.Counter(initial_value = self.bits_to_int(r_padded))
            aes = pyaes.AESModeOfOperationCTR(self.k1, counter = counter)
            plaintext = aes.decrypt(ciphertext)
        
        
        # CBC Mode of Operation
        elif self.modeOfOperation == "CBC":
            (ciphertextBlocks, numBlocks) = self.split_ciphertext_into_blocks(ciphertext)
            
            plaintext = ''
            aes = pyaes.AESModeOfOperationCBC(self.k1, iv = self.bits_to_string(r_padded))
            for i in range(numBlocks):
                plaintext = plaintext + aes.decrypt(ciphertextBlocks[i])
            
            
            
        # CFB Mode of Operation
        elif self.modeOfOperation == "CFB":
            aes = pyaes.AESModeOfOperationCFB(self.k1, iv = self.bits_to_string(r_padded))
            plaintext = aes.decrypt(ciphertext)
            
        # return plaintext
        return plaintext
        


    
    def pad_message_CBC(self, message):
        # TODO
        # pad message so that it is a multiple of 16 bytes
        # returns a list of plaintexts in 16 byte blocks and the number of blocks
        message_bytes = [ ord(c) for c in message ]
        padded_blocks = []
        numBlocks = math.ceil(len(message_bytes)/16.0)
        # pad
        for i in range((numBlocks*16) - len(message_bytes)):
            # TODO change the padding structure so we don't change the final letter of the message
            message_bytes.append(0)
        for i in range(numBlocks/8):
            block = message_bytes[i*8:(i+1)*8]
            string_block = []
            for b in block:
                string_block.append(chr(b))
            padded_blocks.append(string_block)
        
        return (padded_blocks, numBlocks)
            
    def split_ciphertext_into_blocks(self, ciphertext):
        # break the cipher text into blocks of 16 letters
        blocks = []
        block = ''
        for i in range(len(ciphertext)):
            if i%16 == 0:
                blocks.append(block)
                block = ''
            else:
                block = block + ciphertext[i]
        return blocks
            
        
    
    # Takes in message as unicode string, outputs CBC_MAC as a list of bytes (in integer form)
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
            nxt=aes1.encrypt(last^message_bytes[i])
            i+=1
            last=nxt
        nxt=aes2.encrypt(last^message_bytes[n-1])
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
        
    # input is a list of bits, output is a list of ints
    def bits_to_bytes(self, bits):
        byteList = []
        for b in range(len(bits) / 8):
            byte = bits[b*8:(b+1)*8]
            byteList.append(int(''.join([str(bit) for bit in byte]), 2))
        return byteList
        

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

