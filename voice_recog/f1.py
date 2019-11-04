
# coding: utf-8

# In[49]:


import speech_recognition as sr
import pyaudio
import wave
from playsound import playsound
import sounddevice as sd
from scipy.io.wavfile import write
import random
import tkinter as tk
import tkinter
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
import cryptography
from cryptography.fernet import Fernet
import base64, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
#Filelabel = None
#filename = None
#password = None


# In[50]:


def decryptionButton():
    root.withdraw()
    Filelabel = None
    filename = None
    password1 = None
    global key2
    def Dkey(password1):
        global key2
        password1 = passInput1.get().encode()
        salt = b'salt'
        kdf1 = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = salt,
            iterations = 100000,
            backend = default_backend()
        )
        key2 = base64.urlsafe_b64encode(kdf1.derive(password1))
        return(key2)

    def speech2text(Dkey, filename):
        echeck = open('stt.wav','wb')
        scheck = open('stt.txt','wb')
        dcheck = open(filename,'rb')
        ncheck = dcheck.read()
        f = Fernet(key2)
        decrypted =  f.decrypt(ncheck)
        echeck.write(decrypted) 
        r = sr.Recognizer() 
        converter = sr.AudioFile('stt.wav')
        echeck.close()
        with converter as source:
            r.adjust_for_ambient_noise(source, duration=0.2)
            audio = r.record(source)
            message = r.recognize_google(audio)
            message = message.encode()
        os.remove('stt.wav')
        scheck.write(message) 
        
    def saveSpeech():
        global filename, password1
        if filename != None:
            password1 = passInput1.get()
            speech2text(Dkey(password1), filename)
            
                # sys.stdout.write('gonna decrypt the file' + '\n')
                # decrypt_file(fname, password)
        else:
            messagebox.showerror(title="Error", message="There was no file loaded to decrypt")
            
    def check_speech_key():
        messagebox.showinfo(title="INFO", message="Be informed that this module requires an internet connection")
        global key
        nkey = open('password1.txt', 'wb')
        nkey.write(Dkey(password1))
        nkey.close()        
        nkey = open('password1.txt','rb')
        dfile = open('password.txt','rb')
        nkey = nkey.read()
        dfile = dfile.read()
        
        if(dfile == nkey):
            #messagebox.showinfo(title="correct", message="Correct key")
            saveSpeech()
        else:
            messagebox.showerror(title="Error", message="Wrong key")
        root.destroy()
        root3.destroy()

    
       
    
    def Decrypt(key, filename):
        #echeck = open(filename[:-4],'wb')
        echeck = open('Decrypted.wav','wb')
        dcheck = open(filename,'rb')
        ncheck = dcheck.read()
        f = Fernet(key2)
        decrypted =  f.decrypt(ncheck)
        echeck.write(decrypted) 
    
    def saveDecrypted():
        global filename, password1
        if filename != None:
            password1 = passInput1.get()
            Decrypt(Dkey(password1), filename)
            
                # sys.stdout.write('gonna decrypt the file' + '\n')
                # decrypt_file(fname, password)
        else:
            messagebox.showerror(title="Error", message="There was no file loaded to decrypt")
            
    def Play_Audio():
        playsound("Decrypted.wav")
        

    def check_key():
        global key
        nkey = open('password1.txt', 'wb')
        nkey.write(Dkey(password1))
        nkey.close()        
        nkey = open('password1.txt','rb')
        dfile = open('password.txt','rb')
        nkey = nkey.read()
        dfile = dfile.read()
        
        if(dfile == nkey):
            #messagebox.showinfo(title="correct", message="Correct key")
            saveDecrypted()
            Play_Audio()
        else:
            messagebox.showerror(title="Error", message="Wrong key")
        root.destroy()
        root3.destroy()
            
    
    def load_file():
        global password1, filename
        text_file = filedialog.askopenfilename()
        if text_file != None:
            filename = text_file
            var.set(filename)
        print('Selected: ', text_file)  

    
    root3 = tkinter.Tk()
    root3.title("OdCrypt v 1.0 ")
    windowWidth = root3.winfo_reqwidth()
    windowHeight = root3.winfo_reqheight()
    positionRight = int(root3.winfo_screenwidth()/2.5 - windowWidth/2)
    positionDown = int(root3.winfo_screenheight()/3 - windowHeight/2)
    root3.geometry("+{}+{}".format(positionRight, positionDown))
    root3.configure(background='turquoise')
    
    menubar = Menu(root3)
    helpmenu = Menu(menubar, tearoff=0, activebackground='coral', bg='turquoise')
    
    helpmenu.add_command(label="Quit the tool", command=root3.quit)
    menubar.add_cascade(label="Help", menu=helpmenu)
    
    root3.config(menu=menubar)
        
    frame5 = Frame(root3)
    frame5.pack(padx=0, pady=30)
    frame5.configure(background='turquoise')
    
    
    var = StringVar()
    Filelabel = Label(frame5, textvariable=var, relief=FLAT)
    Filelabel.configure(bg='white', fg='Black', anchor=E, font=("default", 8), padx=1, pady=4, activebackground='coral', width=50)
    var.set(" Check the path here !!!")
    Filelabel.pack(side=TOP, padx=10, pady=0)
    
    loadButton = tkinter.Button(frame5, text="   LOAD FILE   ", command=load_file)
    loadButton.pack(side=RIGHT, padx=10, pady=5, fill=X)
    loadButton.configure(bg='turquoise4', fg='white', activebackground='coral')

    frame6 = Frame(root3)
    frame6.pack(padx=0, pady=0)
    frame6.configure(background='turquoise')
    frame7 = Frame(root3)
    frame7.pack(padx=0, pady=40)
    frame7.configure(background='turquoise')
    
    l2 = Label(frame6, text="ENTER KEY")
    l2.configure(background='turquoise')
    passInput1 = Entry(frame6, show="*", width=30)
    password1 = passInput1.get()
    
    decryptButton = tkinter.Button(frame7, text="       DECRYPT      ", command=check_key)
    decryptButton.configure(bg='turquoise4', fg='white', activebackground='coral')
    sttbutton = tkinter.Button(frame7, text="       Sppech 2 Text      ", command=check_speech_key)
    sttbutton.configure(bg='turquoise4', fg='white', activebackground='coral')

    l2.pack(side=LEFT, padx=5, pady=0, fill=X)
    passInput1.pack(side=RIGHT, padx=5, pady=0, fill=X)
    decryptButton.pack(side=RIGHT, padx=10, pady=0, fill=X)
    sttbutton.pack(side=LEFT, padx=10, pady=0, fill=X)
    root3.mainloop()


# In[51]:


def non():
    print('Building in progress')


# In[52]:


def encryptionButton():
    root.withdraw()
    def newR():
        root1.withdraw()
        Filelabel = None
        filename = None
        password = None
        def key(password):
            global key1
            password = passInput.get().encode()
            salt = b'salt'
            kdf = PBKDF2HMAC(
                algorithm = hashes.SHA256(),
                length = 32,
                salt = salt,
                iterations = 100000,
                backend = default_backend()
            )
            key1 = base64.urlsafe_b64encode(kdf.derive(password))
            return(key1)

        def Encrypt(key, filename):
            #ocheck = open(filename+'.enc','wb')
            ocheck = open('Encrypted'+'.enc','wb')
            check = open(filename,'rb')
            ncheck = check.read()
            f = Fernet(key1)
            encrypted =  f.encrypt(ncheck)
            ocheck.write(encrypted)

        def saveEncrypted():
            global filename, password
            if filename != None:
                password = passInput.get()
                Encrypt(key(password), filename)
                # sys.stdout.write('Password is ' + password)
                # encrypt_file(filename, password)
            else:
                messagebox.showerror(title="Error", message="There was no file loaded to encrypt")
            
        def saveKey():
            global dector
            key = open('password.txt', 'wb')
            key.write(key1)
            key.close()

        def load_file():
            global password, filename
            text_file = filedialog.askopenfilename()
            if text_file != None:
                filename = text_file
                var.set(filename)
            print('Selected: ', text_file)  
            
        def rec_file():
            fs = 44100  # Sample rate
            seconds = 10  # Duration of recording

            myrecording = sd.rec(int(seconds * fs), samplerate=fs, channels=2)
            sd.wait()  # Wait until recording is finished
            write('output.wav', fs, myrecording)  # Save as WAV file 

        def sendMessage():
            if (passInput.get() !="" and Filelabel != None):
                saveEncrypted()
                saveKey()
                messagebox.showinfo(title="Sent", message="Your message has been Encrypted")
            else:
                messagebox.showerror(title="Error", message="Message not Sent")
            
            root.destroy()
            root1.destroy()
            root2.destroy()

        root2 = tkinter.Tk()
        root2.title("OdCrypt v 1.0 ")
        windowWidth = root2.winfo_reqwidth()
        windowHeight = root2.winfo_reqheight()
        positionRight = int(root2.winfo_screenwidth()/2.5 - windowWidth/2)
        positionDown = int(root2.winfo_screenheight()/3 - windowHeight/2)
        root2.geometry("+{}+{}".format(positionRight, positionDown))
        root2.configure(background='turquoise')
        menubar = Menu(root2)
        helpmenu = Menu(menubar, tearoff=0, activebackground='coral', bg='turquoise')

        #helpmenu.add_command(label="About AstroCrypt", command=donothing)
        helpmenu.add_command(label="Quit the tool", command=root2.quit)
        menubar.add_cascade(label="Help", menu=helpmenu)

        root2.config(menu=menubar)
        
        frame2 = Frame(root2)
        frame2.pack(padx=0, pady=30)
        frame2.configure(background='turquoise')

        var = StringVar()
        Filelabel = Label(frame2, textvariable=var, relief=FLAT)
        Filelabel.configure(bg='white', fg='Black', anchor=E, font=("default", 10), padx=1, pady=4, activebackground='coral', width=50)
        var.set(" Check the path here !!!")
        Filelabel.pack(side=TOP, padx=10, pady=0)

        loadButton = tkinter.Button(frame2, text="   LOAD FILE   ", command=load_file)
        loadButton.pack(side=RIGHT, padx=10, pady=5, fill=X)
        loadButton.configure(bg='turquoise4', fg='white', activebackground='coral')

        frame3 = Frame(root2)
        frame3.pack(padx=0, pady=0)
        frame3.configure(background='turquoise')
        frame4 = Frame(root2)
        frame4.pack(padx=0, pady=40)
        frame4.configure(background='turquoise')

        l1 = Label(frame3, text="ENTER KEY")
        l1.configure(background='turquoise')
        passInput = Entry(frame3, show="*", width=30)
        password = passInput.get()

        encryptButton = tkinter.Button(frame4, text="       ENCRYPT      ", command=sendMessage)
        encryptButton.configure(bg='turquoise4', fg='white', activebackground='coral')
        
        l1.pack(side=LEFT, padx=5, pady=0, fill=X)
        passInput.pack(side=RIGHT, padx=5, pady=0, fill=X)
        encryptButton.pack(side=LEFT, padx=10, pady=0, fill=X)
        root2.mainloop()
    
    def recordButton():
        root1.withdraw()
        Filelabel = None
        filename = None
        password = None
        
        def key(password):
            global key1
            password = passInput.get().encode()
            salt = b'salt'
            kdf = PBKDF2HMAC(
                algorithm = hashes.SHA256(),
                length = 32,
                salt = salt,
                iterations = 100000,
                backend = default_backend()
            )
            key1 = base64.urlsafe_b64encode(kdf.derive(password))
            return(key1)
        
        def Encrypt(key, filename):    
            filename = 'recorded.wav'
            #ocheck = open(filename+'.enc','wb')
            ocheck = open('Encrypted'+'.enc','wb')
            check = open(filename,'rb')
            ncheck = check.read()
            f = Fernet(key1)
            encrypted =  f.encrypt(ncheck)
            ocheck.write(encrypted)
            
        def saveEncrypted():
            filename = 'recorded.wav'
            global password
            if filename != None:
                password = passInput.get()
                Encrypt(key(password), filename)
                # sys.stdout.write('Password is ' + password)
                # encrypt_file(filename, password)
            else:
                messagebox.showerror(title="Error", message="There was no file loaded to encrypt")
                
        def saveKey():
            key = open('password.txt', 'wb')
            key.write(key1)
            key.close()
            
        def rec_file():
            fs = 44100  # Sample rate
            seconds = 10  # Duration of recording

            myrecording = sd.rec(int(seconds * fs), samplerate=fs, channels=2)
            sd.wait()  # Wait until recording is finished
            write('recorded.wav', fs, myrecording)  # Save as WAV file 
            
        def sendMessage():
            if (passInput.get() !=""):# and Filelabel != None):
                saveEncrypted()
                saveKey()
                messagebox.showinfo(title="Sent", message="Your message has been Encrypted")
            else:
                messagebox.showerror(title="Error", message="Message not Sent")
            
            root.destroy()
            root1.destroy()
            root4.destroy()

            
        
        root4 = tkinter.Tk()
        root4.title("OdCrypt v 1.0 ")
        windowWidth = root4.winfo_reqwidth()
        windowHeight = root4.winfo_reqheight()
        positionRight = int(root4.winfo_screenwidth()/2.5 - windowWidth/2)
        positionDown = int(root4.winfo_screenheight()/3 - windowHeight/2)
        root4.geometry("+{}+{}".format(positionRight, positionDown))
        root4.configure(background='turquoise')
        menubar = Menu(root4)
        helpmenu = Menu(menubar, tearoff=0, activebackground='coral', bg='turquoise')
            
        helpmenu.add_command(label="Quit the tool", command=root4.quit)
        menubar.add_cascade(label="Help", menu=helpmenu)
        root4.config(menu=menubar)
        frame8 = Frame(root4)
        frame8.pack(padx=0, pady=30)
        frame8.configure(background='turquoise')
            
        recordButton = tkinter.Button(frame8, text="   CLICK TO RECORD   ", command=rec_file)
        recordButton.pack(side=RIGHT, padx=10, pady=5, fill=X)
        recordButton.configure(bg='turquoise4', fg='white', activebackground='coral')
            
        frame9 = Frame(root4)
        frame9.pack(padx=0, pady=0)
        frame9.configure(background='turquoise')
        frame10 = Frame(root4)
        frame10.pack(padx=0, pady=40)
        frame10.configure(background='turquoise')
        
        l1 = Label(frame9, text="ENTER KEY")
        l1.configure(background='turquoise')
        passInput = Entry(frame9, show="*", width=30)
        password = passInput.get()
            
        encryptButton = tkinter.Button(frame10, text="       ENCRYPT      ", command=sendMessage)
        encryptButton.configure(bg='turquoise4', fg='white', activebackground='coral')

        l1.pack(side=LEFT, padx=5, pady=0, fill=X)
        passInput.pack(side=RIGHT, padx=5, pady=0, fill=X)
        encryptButton.pack(side=LEFT, padx=10, pady=0, fill=X)
        root4.mainloop()


    root1 = tkinter.Tk()
    root1.title("OdCrypt v 1.0 ")
    windowWidth = root1.winfo_reqwidth()
    windowHeight = root1.winfo_reqheight()
    positionRight = int(root1.winfo_screenwidth()/2 - windowWidth/2)
    positionDown = int(root1.winfo_screenheight()/2 - windowHeight/2)
    root1.geometry("+{}+{}".format(positionRight, positionDown))
    root1.configure(background='turquoise')
    
    menubar = Menu(root1)
    helpmenu = Menu(menubar, tearoff=0, activebackground='coral', bg='turquoise')
     #helpmenu.add_command(label="About AstroCrypt", command=donothing)
    helpmenu.add_command(label="Quit the tool", command=root1.quit)
    menubar.add_cascade(label="Help", menu=helpmenu)
    root1.config(menu=menubar)

    frame1 = Frame(root1)
    frame1.pack(padx=0, pady=40)
    frame1.configure(background='turquoise')
    
    eButton = tkinter.Button(frame1, text="       RECORD      ", command=recordButton)
    eButton.configure(bg='turquoise4', fg='white', activebackground='coral')
    dButton = tkinter.Button(frame1, text="       UPLOAD      ", command=newR)
    dButton.configure(bg='turquoise4', fg='white', activebackground='coral')
    
    eButton.pack(side=LEFT, padx=10, pady=0, fill=X)
    dButton.pack(side=RIGHT, padx=10, pady=0, fill=X)
    root1.mainloop()


# In[53]:


def splashScreen():
    from tkinter import Button, Tk, HORIZONTAL
    from tkinter.ttk import Progressbar
    import time
    import threading
    
    root0 = tkinter.Tk()
    root0.title("OdCrypt v 1.0 ")
    root0.geometry("500x500")
    root0.configure(background='turquoise')
    
    progress=Progressbar(orient=HORIZONTAL,length=100,mode='indeterminate')
    progress.pack()
    
    progress.start()
    time.sleep(15)
    progress.stop()
    progress.grid_forget()

    threading.Thread(target=splashScreen).start()
    
    encryptionButton()
    root0.mainloop()


# In[54]:


root = tkinter.Tk()
root.title("OdCrypt v 1.0 ")
#root.geometry("500x500")
root.configure(background='turquoise')


# In[55]:


windowWidth = root.winfo_reqwidth()
windowHeight = root.winfo_reqheight()
positionRight = int(root.winfo_screenwidth()/2.5 - windowWidth/2)
positionDown = int(root.winfo_screenheight()/3.5 - windowHeight/2)
root.geometry("+{}+{}".format(positionRight, positionDown))


# In[56]:


menubar = Menu(root)
helpmenu = Menu(menubar, tearoff=0, activebackground='coral', bg='turquoise')
 #helpmenu.add_command(label="About AstroCrypt", command=donothing)
helpmenu.add_command(label="Quit the tool", command=root.quit)
menubar.add_cascade(label="Help", menu=helpmenu)
root.config(menu=menubar)


# In[57]:


speech = StringVar()
speech = '''WELCOME!!! 
Odcrypt presents to you a voice recogniton tool with cryptography,With this tool, users can encrypt their audio-file, with a password 
and can keep them safe until it is decrypted using the same password of which is the cryptogrphy aspect,and voice/speech recognition allows the decrypted message to be converted to text incase the user will like to read rather than  listen
THANKS...'''
label1 = Label(root, text=speech,font = ('Bell MT', 15, 'bold'))
label1.configure(wraplength=500, bg='turquoise', fg='Black',activebackground='coral')
label1.pack()


# In[58]:


frame = Frame(root)
frame.pack(padx=0, pady=40)
frame.configure(background='turquoise')


# In[59]:


eButton = tkinter.Button(frame, text="       ENCRYPTION     ", command=encryptionButton)
eButton.configure(bg='turquoise4', fg='white', activebackground='coral')
dButton = tkinter.Button(frame, text="       DECRYPTION      ", command=decryptionButton)
dButton.configure(bg='turquoise4', fg='white', activebackground='coral')


# In[60]:


#l1.pack(side=LEFT, padx=5, pady=0, fill=X)
eButton.pack(side=LEFT, padx=10, pady=0, fill=X)
dButton.pack(side=RIGHT, padx=10, pady=0, fill=X)
root.mainloop()

