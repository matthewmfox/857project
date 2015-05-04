import imp
imp.load_source('pyaes', './pyaes/pyaes/aes.py')
import pyaes

###UFE Regular

class UFE:
    def __init__(self, modeOfOperation, key1, key2, key3, modifiedUFE=False, m2rRatio=0.125):
        self.modeOfOperation = modeOfOperation
        self.k1 = key1
        self.k2 = key2
        self.k3 = key3
        self.modifiedUFE = modifiedUFE
        self.m2rRatio = m2rRatio
        #
    

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
