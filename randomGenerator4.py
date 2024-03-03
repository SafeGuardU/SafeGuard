from tkinter import *
from random import randint

root = Tk()
root.title('Strong Password Generator')
root.iconbitmap('c:/gui/codmey.ico')
root.geometry("500x300")

my_password = chr(randint(33,126))

def new_rand():
    pass

def clipper():
    pass

lf = LabelFrame(root, text="How many Characters?")
lf.pack(pady=20)

my_entry = Entry(lf, font=("Helvetica", 24))
my_entry.pack(pady=20, padx=20)

pw_entry = Entry(root, text="", font=("Helvetica", 24))
pw_entry.pack(pady=20)


my_frame = Frame(root)
my_frame.pack(pady=20)


my_button = Button(my_frame, text="Generate Strong Password", command=new_rand)
my_button.grid(row=0, column=0, padx=10)

clip_button = Button(my_frame, text="Copy To Clipboard", command=clipper)
clip_button.grid(row=0, column=1, padx=10)




root.mainloop()





