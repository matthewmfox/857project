###UFE Regular

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
