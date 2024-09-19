from tkinter import *
from tkinter import messagebox
from dbManger import Db_Server

vpn_server = Db_Server("localhost","mohamed","newpassword","vpn")
vpn_server.clearscn()

def list_out_usernames():
    label = Label(root,text=vpn_server.name_lister())
    label.pack()

def delete_usernames():
    username_input = Entry(root)
    username_input.pack()

    kkbtn = Button(root,text="OK",command=vpn_server.user_remover(username_input.get()))
    kkbtn.pack()


root = Tk()

root.geometry("900x900")
root.title("VPN Database Manager")

btn_delete = Button(root, text="Delete Operation",command=delete_usernames)
btn_delete.pack(pady=10)  # Adds some vertical space between buttons

btn_name_lister = Button(root, text="Usernames List",command=list_out_usernames)
btn_name_lister.pack(pady=10)  # Adds some vertical space between buttons

btn_name_searcher = Button(root, text="Search Usernames")
btn_name_searcher.pack(pady=10)  # Adds some vertical space between buttons


root.mainloop()