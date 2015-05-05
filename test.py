###TEST SCRIPT
from ufe import UFE
import os


if __name__=='__main__':
    key1=os.urandom(16)
    key2=os.urandom(16)
    key3=os.urandom(16)
    CTR = UFE("CTR",key1,key2,key3)
    CBC = UFE("CBC",key1,key2,key3)
    CFB = UFE("CFB",key1,key2,key3)

    ciphertext, sigma = CTR.encrypt("I love 6.857, it's such a great class")
    print repr(ciphertext)
    print "\r"
    print CTR.decrypt(ciphertext,sigma)
    print "\r"

    ciphertext2, sigma2 = CBC.encrypt("We can even unpad our messages that we encode with CBC")
    print repr(ciphertext2)
    print "\r"
    print CBC.decrypt(ciphertext2,sigma2)
    print "\r"

    ciphertext3, sigma3 = CFB.encrypt("Does anyone even use this mode anyway?")
    print repr(ciphertext3)
    print "\r"
    print CFB.decrypt(ciphertext3,sigma3)
    print "\r"
    
