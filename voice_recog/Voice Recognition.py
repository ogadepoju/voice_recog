
# coding: utf-8

# In[1]:


import speech_recognition as sr
import cryptography
from cryptography.fernet import Fernet
import base64, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

r = sr.Recognizer() 
converter = sr.AudioFile('Voice 002.WAV') 


# In[2]:


def SpeechToText(Audio):
    with converter as source:
        r.adjust_for_ambient_noise(source, duration=0.2)
        audio = r.record(source)
    message = r.recognize_google(audio)
    return(message)


# In[3]:


def Encrypt(message):
    password_provided = 'password'
    password = password_provided.encode()
    salt = b'salt'
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )
    key1 = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key1)
    encrypted = f.encrypt(message)
    return(encrypted)


# In[16]:


from gtts import gTTS 
import os 

def TextToSpeech(message):
    password = input('Enter key: ')
    if(password == 'odunayo'):
        mytext = message
        language = 'en'
        myobj = gTTS(text=mytext, lang=language, slow=False) 
        audio = myobj.save("message1.mp3") 
        os.system("mpg123 message1.mp3")
        #return(audio)
    else:
        language = 'en'
        myobj = gTTS(text=encrypted.decode(), lang=language, slow=False) 
        audio = myobj.save("message2.mp3") 
        os.system("mpg123 message2.mp3")
    return(audio)


# In[5]:


def Decrypt(encrypted):
    #password_provided = input('Enter passkey')
    password_provided = 'password'
    password = password_provided.encode()
    salt = b'salt'
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
    )
    key1 = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key1)
    decrypted = f.decrypt(encrypted)
    return(decrypted)


# In[6]:


# message = SpeechToText(converter).encode()


# In[7]:


# message


# In[8]:


# encrypted=Encrypt(message)


# In[9]:


# encrypted


# In[10]:


# message = Decrypt(encrypted)


# In[11]:


# message=message.decode()


# In[15]:


# TextToSpeech(message)