# -*- coding: utf-8 -*-
"""
Created on Fri Dec  9 10:03:42 2016

@author: Duggal
"""

import tkinter
from tkinter import ttk
import tkinter.messagebox
from tkinter import filedialog 

import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

def encrypt(key, filename):
    chunkSize = 64 * 1024
    outFile   = "(encrypt)" + filename.rsplit('/')[-1]
    filepath  = filename.rsplit('/', 1)[0]    
    os.chdir(filepath)
    fileSize  = str(os.path.getsize(filename)).zfill(16)
    IV        = Random.new().read(16)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    with open(filename, 'rb') as InF:
        with open(outFile, 'wb') as OutF:
            OutF.write(fileSize.encode('utf-8'))
            OutF.write(IV)
            while True:
                chunk = InF.read(chunkSize)
                
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                OutF.write(encryptor.encrypt(chunk))
    os.remove(filename)
                
def decrypt(key, filename):
    chunkSize = 64 * 1024
    filepath  = filename.rsplit('/', 1)[0] 
    outFile   = filename.rsplit('/')[-1]
    outFile   = outFile[9:]
    os.chdir(filepath)
    with open(filename, 'rb') as InF:
        fileSize  = int(InF.read(16))
        IV        = InF.read(16)
        
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        
        with open(outFile, 'wb') as OutF:
            while True:
                chunk = InF.read(chunkSize)
                
                if len(chunk) == 0:
                    break
                
                OutF.write(decryptor.decrypt(chunk))
            OutF.truncate(fileSize)
    os.remove(filename)
            
def getKey(password):
    hasher   = SHA256.new(password.encode('utf-8'))
    return hasher.digest()
    
def Main():
   FileName = encrypt_Entry_FileName.get()
   Pass     = encrypt_Entry_Pass.get()     
   ConfPass = encrypt_Entry_ConfPass.get()
   
   if FileName == '':
       emptyField     = tkinter.messagebox.showerror('Empty Fields', 'FileName cannot be empty') 
   elif Pass == '':
       emptyField     = tkinter.messagebox.showerror('Empty Fields', 'Password cannot be empty')
   elif ConfPass == '':
       emptyField     = tkinter.messagebox.showerror('Empty Fields', 'Password cannot be empty') 

   if Pass != ConfPass:
       PassError      = tkinter.messagebox.showerror('Empty Fields', 'Password Does Not Match')
   else:
       try:    
           password = getKey(ConfPass)
           encrypt(password, FileName)
           sucess = tkinter.messagebox.showinfo('Sucess', 'File Sucessfully Encrypted')
           encrypt_Entry_FileName.delete(0, 'end')
           encrypt_Entry_Pass.delete(0, 'end')     
           encrypt_Entry_ConfPass.delete(0, 'end')
       except Exception as er:
           error  = tkinter.messagebox.showerror('Error++++', str(er))
           encrypt_Entry_Pass.delete(0, 'end')     
           encrypt_Entry_ConfPass.delete(0, 'end')
           
def Main_Decrypy():
   FileName = decrypt_Entry_FileName.get()
   Pass     = decrypt_Entry_Pass.get()     
   ConfPass = decrypt_Entry_ConfPass.get() 
   
   if FileName == '':
       emptyField     = tkinter.messagebox.showerror('Empty Fields', 'FileName cannot be empty') 
   elif Pass == '':
       emptyField     = tkinter.messagebox.showerror('Empty Fields', 'Password cannot be empty')
   elif ConfPass == '':
       emptyField     = tkinter.messagebox.showerror('Empty Fields', 'Password cannot be empty') 

   if Pass != ConfPass:
       PassError      = tkinter.messagebox.showerror('Empty Fields', 'Password Does Not Match')
   else:
       try:
           password = getKey(ConfPass)    
           decrypt(password, FileName)
           sucess = tkinter.messagebox.showinfo('Sucess', 'File Sucessfully Decrypted')     
           decrypt_Entry_FileName.delete(0, 'end')
           decrypt_Entry_Pass.delete(0, 'end')     
           decrypt_Entry_ConfPass.delete(0, 'end')
       except Exception as e:
           error  = tkinter.messagebox.showerror('Error', str(e))
           decrypt_Entry_Pass.delete(0, 'end')     
           decrypt_Entry_ConfPass.delete(0, 'end')
       
def clear():
    encrypt_Entry_FileName.delete(0, 'end')
    encrypt_Entry_Pass.delete(0, 'end')     
    encrypt_Entry_ConfPass.delete(0, 'end')
    
    decrypt_Entry_FileName.delete(0, 'end')
    decrypt_Entry_Pass.delete(0, 'end')     
    decrypt_Entry_ConfPass.delete(0, 'end')
    
def fileDialg():
    FileBox = tkinter.filedialog.askopenfilename(initialdir="D:/Tanvir/Python/Prct", filetypes =(("Text File", "*.txt"),("All Files","*.*")))
    encrypt_Entry_FileName.insert(0, FileBox)

def fileDialg_der():
    FileBox = tkinter.filedialog.askopenfilename(initialdir="D:/Tanvir/Python/Prct", filetypes =(("Text File", "*.txt"),("All Files","*.*")))
    decrypt_Entry_FileName.insert(0, FileBox)
    

root = tkinter.Tk()

noteBook = ttk.Notebook(root)
noteBook.pack()

frame_Encrypt = tkinter.Frame(noteBook) 
frame_Decrypt = tkinter.Frame(noteBook)

noteBook.add(frame_Encrypt, text = "Encrypt")
noteBook.add(frame_Decrypt, text = "Decrypt")

#-----------------ENCRYPT GUI----------------------

Label_Line             = tkinter.Label(frame_Encrypt, text = "ENCRYPTOR")
encrypt_Label_FileName = tkinter.Label(frame_Encrypt, text = "Filename")
encrypt_Entry_FileName = tkinter.Entry(frame_Encrypt)
encrypt_Label_Pass     = tkinter.Label(frame_Encrypt, text = "Password") 
encrypt_Entry_Pass     = tkinter.Entry(frame_Encrypt, show = "*")
encrypt_Label_ConfPass = tkinter.Label(frame_Encrypt, text = "Conf Password") 
encrypt_Entry_ConfPass = tkinter.Entry(frame_Encrypt, show = "*")
encrypt_Butt_Submit    = tkinter.Button(frame_Encrypt, text = "Submit", command = Main)
encrypt_Butt_Clear     = tkinter.Button(frame_Encrypt, text = "Clear", command = clear)
encrypt_Butt_File      = tkinter.Button(frame_Encrypt, text = "Open File", command = fileDialg) 

Label_Line.grid(columnspan = 2)
encrypt_Label_FileName.grid(row = 1, sticky = tkinter.E)
encrypt_Entry_FileName.grid(row = 1, column = 1)
encrypt_Butt_File.grid(row = 2, columnspan = 2)
encrypt_Label_Pass.grid(row = 3, sticky = tkinter.E)
encrypt_Entry_Pass.grid(row = 3, column = 1)
encrypt_Label_ConfPass.grid(row = 4, sticky = tkinter.E)
encrypt_Entry_ConfPass.grid(row = 4, column = 1)
encrypt_Butt_Submit.grid(columnspan = 2)
encrypt_Butt_Clear.grid(columnspan = 2)

#-----------------DECRYPT GUI----------------------

d_Label_Line           = tkinter.Label(frame_Decrypt, text = "DECRYPTOR")
decrypt_Label_FileName = tkinter.Label(frame_Decrypt, text = "Filename")
decrypt_Entry_FileName = tkinter.Entry(frame_Decrypt)
decrypt_Label_Pass     = tkinter.Label(frame_Decrypt, text = "Password") 
decrypt_Entry_Pass     = tkinter.Entry(frame_Decrypt, show = "*")
decrypt_Label_ConfPass = tkinter.Label(frame_Decrypt, text = "Conf Password") 
decrypt_Entry_ConfPass = tkinter.Entry(frame_Decrypt, show = "*")
decrypt_Butt_Submit    = tkinter.Button(frame_Decrypt, text = "Submit", command = Main_Decrypy)
decrypt_Butt_Clear     = tkinter.Button(frame_Decrypt, text = "Clear", command = clear)
decrypt_Butt_File      = tkinter.Button(frame_Decrypt, text = "Open File", command = fileDialg_der) 

d_Label_Line.grid(columnspan = 2)
decrypt_Label_FileName.grid(row = 1, sticky = tkinter.E)
decrypt_Entry_FileName.grid(row = 1, column = 1)
decrypt_Butt_File.grid(row = 2, columnspan = 2)
decrypt_Label_Pass.grid(row = 3, sticky = tkinter.E)
decrypt_Entry_Pass.grid(row = 3, column = 1)
decrypt_Label_ConfPass.grid(row = 4, sticky = tkinter.E)
decrypt_Entry_ConfPass.grid(row = 4, column = 1)
decrypt_Butt_Submit.grid(columnspan = 2)
decrypt_Butt_Clear.grid(columnspan = 2)


root.mainloop()