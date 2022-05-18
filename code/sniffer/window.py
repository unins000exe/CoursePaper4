import tkinter as tk
from tkinter import ttk
import socket
import sniffer
from datetime import datetime


class Menu(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.grid(row=0, column=0, sticky=tk.NSEW)

        self.output = tk.Text(width=200, height=50)
        self.output.grid(row=0, column=1)

        self.scroll_out = ttk.Scrollbar(command=self.output.yview)
        self.scroll_out.grid(row=0, column=1)
        self.output.config(yscrollcommand=self.scroll_out.set)

        self.st = ttk.Button(self, text="start", command=self.sniff)
        self.st.grid(row=0, column=0)

        self.last_out = []


    def sniff(self):
        out = sniffer.main(conn)
        if out != self.last_out:
            # print(out)
            self.output.insert('end', str(datetime.now().strftime('%H:%M:%S')) + ":\n")
            for s in out:
                self.output.insert('end', s + '\n')
            self.last_out = out
        root.after(500, self.sniff)  # ?


conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
root = tk.Tk()
root.title("Sniffer")
menu = Menu(root)
root.mainloop()