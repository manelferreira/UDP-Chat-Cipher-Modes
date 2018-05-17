# -*- coding: utf-8 -*-

from Tkinter import *
import socket
from threading import Thread
from random import randint, choice
import random

class SDES:
    key = "1010000010"

    P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)

    P8 = (6, 3, 7, 4, 8, 5, 10, 9)

    P4 = (2, 3, 4, 1)

    IP = (2, 6, 3, 1, 4, 8, 5, 7)
    IPi = (4, 1, 3, 5, 7, 2, 8, 6)

    S0 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 3, 2]
        ]

    S1 = [
            [0, 1, 2, 3],
            [2, 0, 1, 3],
            [3, 0, 1, 0],
            [2, 1, 0, 3]
        ]

    E = (4, 1, 2, 3, 2, 3, 4, 1)

    def encrypt(self, cipher):
        p10key = self.permute(self.P10, self.key)
        
        left = p10key[:len(p10key)/2]
        right = p10key[len(p10key)/2:]

        first_key = self.generate_first_key(left, right)
        second_key = self.generate_second_key(left, right)

        permuted_cipher = self.permute(self.IP, cipher)

        cipher_left = permuted_cipher[:len(permuted_cipher)/2]
        cipher_right = permuted_cipher[len(permuted_cipher)/2:]
        
        left, right = self.f(cipher_left, cipher_right, first_key)
        left, right = self.f(right, left, second_key)

        encrypted = self.permute(self.IPi, left + right)

        return encrypted

    def permute(self, permutation, key):
        permutated = ""
        for i in permutation:
            permutated += key[i-1]
        return permutated

    def generate_first_key(self, left, right):
        left_key = left[1:] + left[:1] 
        right_key = right[1:] + right[:1]
        key = left_key + right_key
        return self.permute(self.P8, self.key)

    def generate_second_key(self, left, right):
        left_key = left[3:] + left[:3] 
        right_key = right[3:] + right[:3]
        key = left_key + right_key
        return self.permute(self.P8, self.key)

    def prepareStrCounter(self, blockLength, counter):
        strCounter = ""

        for i in range(0, (blockLength - len(counter))):
            strCounter += str(0)

        strCounter += counter

        # print("Counter string = " + strCounter  + " for key = " + counter)

        return strCounter

    def XOR(self, cipher, key):
        xorado = ""
        for i in range(0, len(cipher)):
            if cipher[i] == key[i]:
                xorado += str(0)
            else:
                xorado += str(1)
        return xorado

    def F(self, right, subkey):
        right_expandido = self.permute(self.E, right)
        
        xorado = self.XOR(right_expandido, subkey)
        
        cipher_xor_left = xorado[:4]    
        cipher_xor_right = xorado[4:]

        cipher_sbox_left = self.Sbox(cipher_xor_left, self.S0)
        cipher_sbox_right = self.Sbox(cipher_xor_right, self.S1)
        cipher_sbox = cipher_sbox_left + cipher_sbox_right
        
        return self.permute(self.P4, cipher_sbox)

    def Sbox(self, input, sbox):
        lin = int(input[0] + input[3], 2)
        col = int(input[1] + input[2], 2)
        
        return bin(sbox[lin][col])[2:].zfill(2)

    def f(self, first_half, second_half, key):
        xorado = self.XOR(first_half, self.F(second_half, key))
        final = xorado + second_half
        
        return final[:4], second_half

class ECB:
    def encrypt(self, plainText):
        # cipherMode 2 bits
        encrypted = "00"
        sdes = SDES()

        # print("\n=============== ECB ENCRYPTING ================")
        # print("Plain text passing through ECB: " + plainText)

        times = len(plainText)/8

        for i in range(0, times):
            block = plainText[i*8:((i+1)*8)]
            encryptedBlock = sdes.encrypt(block)
            encrypted += encryptedBlock

        return encrypted

    def decrypt(self, encrypted):
        plainTextBits = ""

        sdes = SDES()

        times = len(encrypted)/8

        for i in range(0, times):
            block = encrypted[i*8:((i+1)*8)]
            decryptedBlock = sdes.encrypt(block)
            plainTextBits += decryptedBlock

        return plainTextBits

class CTR:
    def encrypt(self, plainText):
        # cipherMode 2 bits
        encrypted = "01"

        # print("\n=============== CTR ENCRYPTING ================")
        # print("Plain text passing through CTR: " + plainText)

        sdes = SDES()

        counter = "0"

        times = len(plainText)/8

        for i in range(0, times):
            block = plainText[i*8:((i+1)*8)]

            strCounter = sdes.prepareStrCounter(len(block), counter)
            strCounter = sdes.encrypt(strCounter)
            encryptedBlock = sdes.XOR(block, strCounter)
            
            counter = int(counter) + 1
            counter = str(counter)

            encrypted += encryptedBlock

        return encrypted

    def decrypt(self, encrypted):
        plainTextBits = ""
        
        sdes = SDES()

        counter = "0"

        times = len(encrypted)/8

        for i in range(0, times):
            block = encrypted[i*8:((i+1)*8)]

            strCounter = sdes.prepareStrCounter(len(block), counter)
            strCounter = sdes.encrypt(strCounter)
            decryptedBlock = sdes.XOR(block, strCounter)
            
            counter = int(counter) + 1
            counter = str(counter)

            plainTextBits += decryptedBlock

        return plainTextBits

class CBC:
    def encrypt(self, plainText):
        # cipherMode 2 bits
        encrypted = "10"

        sdes = SDES()

        initialVector = ""
        for _ in range(8):
            initialVector += str(random.randint(0, 1))
        
        # print("\nGENERATED IV: " + initialVector)
        
        # print("\n=============== CBC ENCRYPTING ================")
        # print("\nPlain text passing through CBC: " + plainText)

        block = plainText[:8]
        xorado = sdes.XOR(block, initialVector)
        encryptedBlock = sdes.encrypt(xorado)
        last = encryptedBlock

        encrypted += encryptedBlock

        times = len(plainText)/8

        for i in range(1, times):
            block = plainText[i*8:((i+1)*8)]

            xorado = sdes.XOR(block, last)
            encryptedBlock = sdes.encrypt(xorado)
            last = encryptedBlock

            encrypted += encryptedBlock

        # initial vector bits
        encrypted += initialVector

        return encrypted

    def decrypt(self, encrypted):
        plainTextBits = ""

        sdes = SDES()

        initialVector = encrypted[(len(encrypted)-8):]
        # print("\nRECEIVED IV: " + initialVector)
        encrypted = encrypted[:(len(encrypted)-8)]

        # print("\n=============== CBC DECRYPTING ================");
        # print("\nReceived encrypted: " + encrypted)

        block = encrypted[:8]
        decryptedBlock = sdes.encrypt(block)
        decryptedBlock = sdes.XOR(decryptedBlock, initialVector)    
        last = block

        plainTextBits += decryptedBlock

        times = len(encrypted)/8

        for i in range(1, times):
            block = encrypted[i*8:((i+1)*8)]

            decryptedBlock = sdes.encrypt(block)
            decryptedBlock = sdes.XOR(decryptedBlock, last)
            last = block

            plainTextBits += decryptedBlock

        return plainTextBits


class stringBitsUtils:
    def strToBits(self, s):
        result = ""
        for c in s:
            bits = bin(ord(c))[2:]
            bits = '00000000'[len(bits):] + bits
            result += bits
        return result

    def bitsToStr(self, bits):
        chars = []
        for b in range(len(bits) / 8):
            byte = bits[b*8:(b+1)*8]
            chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
        return ''.join(chars)


####################################################################################
############################# INTERFACE AND SOCKETS ################################
####################################################################################
class Receive():
    def __init__(self, server, messagesLog):
        self.server = server
        self.messagesLog = messagesLog

        while 1:
            try:
                text = self.server.recv(1024)

                cipherMode = text[:2]
                text = text[2:]
                # print("\nReceived text in bits: " + text)
                if cipherMode == "00":
                    text = ECB().decrypt(text)
                    # print("\nDecrypted Text in bits: " + text)
                    text = stringBitsUtils().bitsToStr(text)
                    # print("\nDecrypted Text: " + text)

                elif cipherMode == "01":
                    text = CTR().decrypt(text)
                    # print("\nDecrypted Text in bits: " + text)
                    text = stringBitsUtils().bitsToStr(text)
                    # print("\nDecrypted Text: " + text)

                elif cipherMode == "10":
                    text = CBC().decrypt(text)
                    # print("\nDecrypted Text in bits: " + text)
                    text = stringBitsUtils().bitsToStr(text)
                    # print("\nDecrypted Text: " + text)

                messagesLog.insert(INSERT, text + "\n")
            except Exception as e:
                print(e)
                break

class App(Thread):
    RECEIVE_UDP_ON_IP = "127.0.0.1"
    RECEIVE_UDP_ON_PORT = 5005

    server = socket.socket(socket.AF_INET, # Internet
                socket.SOCK_DGRAM) # UDP
    server.bind((RECEIVE_UDP_ON_IP, RECEIVE_UDP_ON_PORT))

    def __init__(self, master):
        Thread.__init__(self)
        # text to show messages
        self.text = Text(master)
        self.text.pack()

        # inputs - IP AND PORT
        ipLabelVar = StringVar()
        ipLabel = Label(master, textvariable = ipLabelVar)
        ipLabelVar.set("Destination IP Address:")
        ipLabel.pack()

        entryIP = Entry(master, width = 15)
        entryIP.pack()

        portLabelVar = StringVar()
        portLabel = Label(master, textvariable = portLabelVar)
        portLabelVar.set("Destination Port:")
        portLabel.pack()

        entryPort = Entry(master, width = 5)
        entryPort.pack()

        # dropdown menu - select cipher mode
        cipherVar = StringVar()
        cipherLabel = Label(master, textvariable = cipherVar)
        cipherVar.set("Select the cipher mode:")
        cipherLabel.pack()

        cipherMode = StringVar(master)
        cipherMode.set("ECB") # default value

        dropDownCipherMode = OptionMenu(master, cipherMode, "ECB", "CBC", "CTR")
        dropDownCipherMode.pack()

        # input - MESSAGE CONTENT
        entryMessage = Entry(master, width = 70)
        entryMessage.pack()

        entryIP.focus_set()
        
        # button - SEND MESSAGE
        def getEntryText():
            # text.insert(INSERT, entryMessage.get())
            message = "Message from " + self.RECEIVE_UDP_ON_IP + ": " + entryMessage.get()
            self.text.insert(INSERT, "Message sent: " + entryMessage.get() + "\n")
            UDP_IP = entryIP.get()
            UDP_PORT = int(entryPort.get())

            # transform string to bits
            message = stringBitsUtils().strToBits(message)
            # print(message)

            if cipherMode.get() == "ECB":
                message = ECB().encrypt(message)
            elif cipherMode.get() == "CTR":
                message = CTR().encrypt(message)
            elif cipherMode.get() == "CBC":
                message = CBC().encrypt(message)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            sock.sendto(message, (UDP_IP, UDP_PORT))
            entryMessage.delete(0, 'end')

        sendButton = Button(master, text="Send message", width=10, command=getEntryText)
        sendButton.pack()

    def run(self):
        Receive(self.server, self.text)

master = Tk()
master.title("UDP Cipher Chat")
app = App(master).start()

mainloop()
