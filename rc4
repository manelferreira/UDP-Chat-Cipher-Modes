# -*- coding: utf-8 -*-

from Tkinter import *
import socket
from threading import Thread
from random import randint, choice
import random
import sys

class RC4:
    S = []
    p = q = None
    key = "skioaujh"

    def __init__(self):
        self.key = self.convertKey()

    def KSA(self): # Key Scheduling Algorithm
        self.p = 0 
        self.q = 0
        keylenght = len(self.key)
        # Usado para inicializar a permutação no array S.

        # primeiro preenchemos o array S com valores de 0 à 255
        self.S = range(256)

        # depois somamos o valor de j, o valor de S apontado por i e o 
        # valor de K (chave) apontado por i e armazenamos na variável j.
        # trocamos os valores entre S[i] e S[j]
        j = 0
        for i in range(256):
            j = (j + self.S[i] + self.key[i % keylenght]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def PRGA(self): # Pseudo-Random Generation Algorithm
        # Para todas repetições necessárias, o PRGA modifica o estado e 
        # a saída do byte resultante. Em cada repetição:

        # O PRGA incrementa em 1 a variável p.
        self.p = (self.p + 1) % 256

        ## Adiciona o valor de S apontado por p com q e armazena o resultado em q.
        self.q = (self.q + self.S[self.p]) % 256

        ## Troca os valores entre S[p] e S[q].
        self.S[self.p], self.S[self.q] = self.S[self.q], self.S[self.p]

        ## A saída é então calculada entre o valor de S 
        ## apontado por S[p] + S[q] que será Xorada com a mensagem original.
        return self.S[(self.S[self.p] + self.S[self.q]) % 256]

    def encrypt(self, plainText):
    
        self.KSA()

        return "".join("%02X" % (ord(c) ^ self.PRGA()) for c in plainText)

    def decrypt(self, cipher):
        
        self.KSA()
            
        byteList = []
        for i in range(0, len(cipher), 2):
            byte = cipher[i:i+2]
            byteList.append(int(byte, 16))

        return "".join([chr(byte ^ self.PRGA()) for byte in byteList])

    def convertKey(self):
        return [ord(c) for c in self.key]


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

                text = RC4().decrypt(text)

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

            message = RC4().encrypt(message)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            sock.sendto(message, (UDP_IP, UDP_PORT))
            entryMessage.delete(0, 'end')

        sendButton = Button(master, text="Send message", width=10, command=getEntryText)
        sendButton.pack()

    def run(self):
        Receive(self.server, self.text)

master = Tk()
master.title("UDP RC4 Chat")
app = App(master).start()

mainloop()
