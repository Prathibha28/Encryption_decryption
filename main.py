from tkinter import *
import speech_recognition as sr
import random
# module for encryption and decryption
import base64
# creating tk object
tk = Tk()
# defining size of window
tk.geometry("1200x600")
# setting up the title of window
tk.title("secret code")
tk.config(bg='light pink')

Top = Frame(tk, width=1600, relief=RAISED)
Top.pack(side=TOP)

f1 = Frame(tk, width=1600, relief=GROOVE,bg='light pink')
f1.pack(side=LEFT)

title_e = Label(Top, font=('times new roman', 48, 'bold'),
                text="SECRET MESSAGE \n ENCRYPT AND DECRYPT",
                fg="Black",bg='light pink')

title_e.grid(row=0, column=0,columnspan=3)

# Initialize variables
Msg = StringVar()
Msg_d=StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()

txtMsg = Entry(f1, font=('arial', 16, 'bold'),
               textvariable=Msg,bd=10, insertwidth=10,
               bg="powder blue", justify='right')
txtMsg.grid(row=1, column=1)

t_msg_d = Label(f1, font=('times new roman', 16, 'bold'),
              text="MESSAGE to decrpyt:",bg='light pink',padx=30)
t_msg_d.grid(row=1, column=2)


txtMsg_d = Entry(f1, font=('arial', 16, 'bold'),
               textvariable=Msg_d,bd=10, insertwidth=10,
               bg="powder blue", justify='right')

txtMsg_d.grid(row=1, column=3)


t_key = Label(f1, font=('times new roman', 16, 'bold'),
              text="KEY (Only Integer)",bd=30,bg='light pink')

t_key.grid(row=2, column=0)

txtkey = Entry(f1, font=('times new roman', 16, 'bold'),
               textvariable=key, bd=10, insertwidth=4,
               bg="powder blue", justify='right',show='*')

txtkey.grid(row=2, column=1)

t_mode = Label(f1, font=('times new roman', 16, 'bold'),
               text="MODE(e-encrypt, d-decrypt):",
               bd=10,bg='light pink',padx=30)

t_mode.grid(row=3, column=1)

txtmode = Entry(f1, font=('times new roman', 16, 'bold'),
                textvariable=mode, bd=10, insertwidth=4,
                bg="powder blue", justify='right')

txtmode.grid(row=3, column=2,pady=30)

t_Result = Label(f1, font=('times new roman', 16, 'bold'),
                 text="Result:",bg='light pink')

t_Result.grid(row=2, column=2)

txtResult = Entry(f1, font=('times new roman', 16, 'bold'),
                  textvariable=Result, bd=10, insertwidth=4,
                  bg="powder blue", justify='right')

txtResult.grid(row=2, column=3)

# Function to encode

def encode(key, msg):
    enc = []
    for i in range(len(msg)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(msg[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode())

# Function to decode

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def Results():

    k = key.get()
    m = mode.get()

    if (m == 'e'):
        Msg_d.set("")
        Result.set("")
        msg = Msg.get()
        Result.set(encode(k, msg))
    else:
        Msg.set("")
        Result.set("")
        msg = Msg_d.get()
        Result.set(decode(k, msg))

# exit function

def qExit():
    tk.destroy()

# Function to reset

def Reset():

    Msg.set("")
    Msg_d.set("")
    key.set("")
    mode.set("")
    Result.set("")

def listen():
    r=sr.Recognizer()
    with sr.Microphone() as source:
        audio_data = r.listen(source)
        try:
            txt=r.recognize_google(audio_data)
        except sr.UnknownValueError:
            print("could not understand")
            qExit()
        except sr.RequestError:
            print("Not able to request result from google")
            qExit()
        Msg.set(txt)

b_listen=Button(f1, padx=25, pady=10, bd=16, fg="black",
                 font=('times new roman', 16, 'bold'), width=10,
                 text="SPEAK-to encrypt", bg="orange",
                 command=listen).grid(row=1, column=0)

b_total = Button(f1, padx=15, pady=10, bd=16, fg="black",
                 font=('times new roman', 16, 'bold'), width=10,
                 text="Show Message", bg="orange",
                 command=Results).grid(row=5, column=1)

b_reset = Button(f1, padx=15, pady=10, bd=16,
                 fg="black", font=('times new roman', 16, 'bold'),
                 width=10, text="Reset", bg="light green",
                 command=Reset).grid(row=5, column=2)

b_exit = Button(f1, padx=15, pady=10, bd=16,
                fg="black", font=('times new roman', 16, 'bold'),
                width=10, text="Exit", bg="red",
                command=qExit).grid(row=5, column=3)

tk.mainloop()
