import imp
imp.load_source('pyaes', './pyaes/pyaes/aes.py')
import pyaes
import os
import math
import random
import time
import string

class UFE:
    def __init__(self, modeOfOperation, key1, key2, key3, modifiedUFE=False, m2rRatio=16):
        self.modeOfOperation = modeOfOperation
        self.k1 = key1
        self.k2 = key2
        self.k3 = key3
        self.modifiedUFE = modifiedUFE
        self.m2rRatio = m2rRatio
        self.blockSize = 128

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
            #aes = pyaes.AESModeOfOperationCFB(self.k1, iv = self.bits_to_string(r_padded))
            aes = pyaes.AESModeOfOperationCFB(self.k1, iv = self.bits_to_string(r_padded), segment_size = 16)
            ciphertext = aes.encrypt(message)
            
        # create CBC-MAC of ciphertext
        CBC_MAC = self.cbc_mac(ciphertext)
        
        
        # CBC_MAC is a list of bytes represented as integers
        # xor CMB_MAC with r
        ##THINK ABOUT THIS
        r = self.bits_to_bytes(r_padded)
        sigma = []
        for i in range(len(r_original)):
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
        
        r_padded = self.pad_r(r_original)
        
        
        # decrypt using AES
        if self.modeOfOperation == "CTR":
            counter = pyaes.Counter(initial_value = self.bits_to_int(r_padded))
            aes = pyaes.AESModeOfOperationCTR(self.k1, counter = counter)
            plaintext = aes.decrypt(ciphertext)
        
        
        # CBC Mode of Operation
        elif self.modeOfOperation == "CBC":
            ciphertextBlocks = self.split_ciphertext_into_blocks(ciphertext)
            numBlocks=len(ciphertextBlocks)
            plaintext = ''
            aes = pyaes.AESModeOfOperationCBC(self.k1, iv = self.bits_to_string(r_padded))
            for i in range(numBlocks):
                plaintext = plaintext + aes.decrypt(ciphertextBlocks[i])
            plaintext=self.unpad_message_CBC(plaintext)
            
            
        # CFB Mode of Operation
        elif self.modeOfOperation == "CFB":
            aes = pyaes.AESModeOfOperationCFB(self.k1, iv = self.bits_to_string(r_padded), segment_size = 16)
            plaintext = aes.decrypt(ciphertext)
            
        # return plaintext
        return plaintext
        


    
    def pad_message_CBC(self, message):
        # TODO
        # pad message so that it is a multiple of 16 bytes
        # returns a list of plaintexts in 16 byte blocks and the number of blocks
        message_bytes = [ ord(c) for c in message ]
        padded_blocks = []
        numBlocks = int(math.ceil(len(message_bytes)/16.0))
        # pad
        for i in range((numBlocks*16) - len(message_bytes)):
            # TODO change the padding structure so we don't change the final letter of the message
            message_bytes.append(0)
        for i in range(numBlocks):
            block = message_bytes[i*16:(i+1)*16]
            string_block = []
            for b in block:
                string_block.append(chr(b))
            padded_blocks.append(string_block)
        
        return (padded_blocks, numBlocks)

    def unpad_message_CBC(self,message):
        message_bytes = [ ord(c) for c in message if ord(c)!=0]
        return "".join([chr(x) for x in message_bytes])

                    
    def split_ciphertext_into_blocks(self, ciphertext):
        # break the cipher text into blocks of 16 letters
        blocks = []
        block = ''
        for i in range(len(ciphertext)):
            block = block + str(ciphertext[i])
            if (i+1)%16 == 0:
                blocks.append(block)
                block = ''
        return blocks
            
        
    
    # Takes in message as unicode string, outputs CBC_MAC as a list of bytes (in integer form)
    def cbc_mac(self, ciphertext):
        aes1 = pyaes.AESModeOfOperationCBC(self.k2)
        # convert message to bytes
        #blocks = [ ord(c) for c in ciphertext ]
        blocks = self.split_ciphertext_into_blocks(self.string_to_bits(ciphertext))
        #ciphertext = aes.encrypt(plaintext_bytes)
        n = len(blocks)
        for i in range(n-1):
            nxt=aes1.encrypt(blocks[i])
        aes2 = pyaes.AESModeOfOperationCBC(self.k3,iv = nxt)
        nxt=self.bits_to_bytes(self.string_to_bits(aes2.encrypt(blocks[n-1])))
        return nxt
        
        
    # returns a list, first element is r without padding represented as list of bits
    # second element is r with padding represented as list of bits
    def eugenes_large_erection(self, message):
        # Eugene get this shit done
        result = []
        messageBitArray = self.string_to_bits(message)
        if self.modifiedUFE:
            lengthOfR = int(math.ceil(len(messageBitArray)*self.m2rRatio))
            if lengthOfR>16:
                lengthOfR=16
        else:
            lengthOfR = 16
        rand = random.getrandbits(lengthOfR)
        rand = self.int_to_bitlist(rand)
        for item in rand:
            result.append(item)
        while len(result) < self.blockSize:
            result.append(0)
        return result,rand


    # input is a list of bits, output is a list of ints
    def bits_to_bytes(self, bits):
        byteList = []
        for b in range(len(bits) / 8):
            byte = bits[b*8:(b+1)*8]
            byteList.append(int(''.join([str(bit) for bit in byte]), 2))
        return byteList

    # input is a list of bits
    def bits_to_string(self, bits):
        chars = []
        for b in range(len(bits) / 8):
            byte = bits[b*8:(b+1)*8]
            chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
        return ''.join(chars)

    # input is list of bits, returns integer
    def bits_to_int(self, bits):
        e = 0
        res = 0
        for i in reversed(range(len(bits))):
            if bits[i] == 1:
                res = res + (2**e)
            e = e + 1
        return res

    # converts an integer into a list of bits
    def int_to_bitlist(self, n):
        return [int(digit) for digit in bin(n)[2:]]

    def pad_r(self, r):
        res = []
        while len(r) < self.blockSize:
            r.append(0)
        res = r
        return res

    # returns a list of bits
    def string_to_bits(self, s):
        result = []
        for c in s:
            bits = bin(ord(c))[2:]
            bits = '00000000'[len(bits):] + bits
            result.extend([int(b) for b in bits])
        return result





####### MODES OF OPERATION PERFORMANCE TESTING

def MOO_performance_testing(message):
    
    # generate keys (128 bit)
    key1 = os.urandom(16)
    key2 = os.urandom(16)
    key3 = os.urandom(16)
    
    # create the UFEs, one for each mode
    UFE_CTR = UFE("CTR", key1, key2, key3)
    UFE_CBC = UFE("CBC", key1, key2, key3)
    UFE_CFB = UFE("CFB", key1, key2, key3)
    
    
    # TESTING SPEED OF CTR
    
    CTR_start = time.clock()
    # encrypt using CTR
    (CTR_ciphertext, CTR_sigma) = UFE_CTR.encrypt(message)
    CTR_enc_done = time.clock()
    # decrypt using CTR
    CTR_plaintext = UFE_CTR.decrypt(CTR_ciphertext, CTR_sigma)
    CTR_dec_done = time.clock()
    # check that UFE worked correctly
    assert CTR_plaintext == message, "UFE_CTR failed"
    CTR_enc_time = CTR_enc_done-CTR_start
    CTR_dec_time = CTR_dec_done-CTR_enc_done
    
    
    
    # TESTING SPEED OF CBC
    
    CBC_start = time.clock()
    # encrypt using CBC 
    (CBC_ciphertext, CBC_sigma) = UFE_CBC.encrypt(message)
    CBC_enc_done = time.clock()
    # decrypt using CBC
    CBC_plaintext = UFE_CBC.decrypt(CBC_ciphertext, CBC_sigma)
    CBC_dec_done = time.clock()
    # check that UFE worked correctly
    assert CBC_plaintext == message, "UFE_CBC failed"
    CBC_enc_time = CBC_enc_done-CBC_start
    CBC_dec_time = CBC_dec_done-CBC_enc_done
    
    
    
    
    # TESTING SPEED OF CFB
    
    CFB_start = time.clock()
    # encrypt using CFB 
    (CFB_ciphertext, CFB_sigma) = UFE_CFB.encrypt(message)
    CFB_enc_done = time.clock()
    # decrypt using CFB
    CFB_plaintext = UFE_CFB.decrypt(CFB_ciphertext, CFB_sigma)
    CFB_dec_done = time.clock()
    # check that UFE worked properly
    assert CFB_plaintext == message, "UFE_CFB failed"
    CFB_enc_time = CFB_enc_done-CFB_start
    CFB_dec_time = CFB_dec_done-CFB_enc_done
    
    # returns [CTR_speed_triple, CBC_speed_triple, CFB_speed_triple]
    return [(CTR_enc_time, CTR_dec_time, CTR_enc_time+CTR_dec_time), (CBC_enc_time, CBC_dec_time, CBC_enc_time+CBC_dec_time), (CFB_enc_time, CFB_dec_time, CFB_enc_time+CFB_dec_time)]





def repeated_performance_testing_MOO(string_length=160, repetitions=5000):
    results = []
    for i in range(repetitions):
        # create the random stirng
        random_message = ''.join(random.SystemRandom().choice(string.printable) for _ in range(string_length))
        result = MOO_performance_testing(random_message)
        
        results.append(result)

            
        
    # group results by MOO
    CTR_results = []
    CBC_results = []
    CFB_results = []
    for i in range(repetitions):
        CTR_results.append(results[i][0])
        CBC_results.append(results[i][1])
        CFB_results.append(results[i][2])
    
    # find the averages
    CTR_enc_sum = 0
    CTR_dec_sum = 0
    CBC_enc_sum = 0
    CBC_dec_sum = 0
    CFB_enc_sum = 0
    CFB_dec_sum = 0
    
    for i in range(repetitions):
        CTR_enc_sum += CTR_results[i][0]
        CTR_dec_sum += CTR_results[i][0]
        CBC_enc_sum += CBC_results[i][0]
        CBC_dec_sum += CBC_results[i][1]
        CFB_enc_sum += CFB_results[i][0]
        CFB_dec_sum += CFB_results[i][1]
        
    div = float(repetitions)
    CTR_avgs = (CTR_enc_sum/div, CTR_dec_sum/div)
    CBC_avgs = (CBC_enc_sum/div, CBC_dec_sum/div)
    CFB_avgs = (CFB_enc_sum/div, CFB_dec_sum/div)
    return [CTR_avgs, CBC_avgs, CFB_avgs]


############# m2r PERFORMANCE TESTING

def m2r_performance_testing(message, m2rRatio):
    
    # generate keys (128 bit)
    key1 = os.urandom(16)
    key2 = os.urandom(16)
    key3 = os.urandom(16)
    
    # create the UFEs, one for each mode
    ufe = UFE("CTR", key1, key2, key3, modifiedUFE=True, m2rRatio=m2rRatio)
    
    
    
    # TESTING SPEED OF CTR
    
    start = time.clock()
    # encrypt using CTR
    (ciphertext, sigma) = ufe.encrypt(message)
    enc_done = time.clock()
    # decrypt using CTR
    plaintext = ufe.decrypt(ciphertext, sigma)
    dec_done = time.clock()
    # check that UFE worked correctly
    assert plaintext == message, "UFE failed"
    enc_time = enc_done-start
    dec_time = dec_done-enc_done

        
    return (enc_time, dec_time)
    
    
def repeated_performance_testing_m2r(string_length=160, repetitions=500, m2rRatios = [10, 15, 20, 25, 30, 35, 40]):
    allResults = {}
    for m2rRatio in m2rRatios:
        results = []
        for i in range(repetitions):
            # create the random stirng
            random_message = ''.join(random.SystemRandom().choice(string.printable) for _ in range(string_length))
            result = m2r_performance_testing(random_message, m2rRatio)
            results.append(result)
        allResults[str(m2rRatio)] = results
    
    for k in allResults.keys():
        r = allResults[k]
        encTotal = 0
        decTotal = 0
        for i in range(repetitions):
            encTotal += r[i][0]
            decTotal += r[i][1]
        encAvg = encTotal/float(repetitions)
        decAvg = decTotal/float(repetitions)
        allResults[k] = (encAvg, decAvg)
        
            
    return allResults
    
    


    