#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk
import socket
import sniffer
from datetime import datetime

TAB_2 = '\t * '

class Menu(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.grid(row=0, column=0, sticky=tk.NSEW)

        self.label1 = ttk.Label(self, text='Вывод TCP/UDP трафика')
        self.label1.grid(row=0, column=0, pady=5)

        self.output = tk.Text(self, width=75, height=35)
        self.output.grid(row=1, column=0, padx=(5, 0), sticky=tk.NW)

        self.scroll_out = ttk.Scrollbar(self, command=self.output.yview)
        self.scroll_out.grid(row=1, column=1, padx=(0, 15))
        self.output.config(yscrollcommand=self.scroll_out.set)

        self.label2 = ttk.Label(self, text='Список IP-адресов, взаимодействующих с ' + UIP + ' через P2P')
        self.label2.grid(row=0, column=2, pady=5, sticky=tk.N)

        self.p2p_lb = tk.Listbox(self, height=30)
        self.p2p_lb.grid(row=1, column=2, sticky=tk.N)

        self.scroll_p2p_lb = ttk.Scrollbar(self, command=self.output.yview)
        self.scroll_p2p_lb.grid(row=1, column=3, padx=(0, 5))
        self.p2p_lb.config(yscrollcommand=self.scroll_p2p_lb.set)

        self.sniff()
        self.find_p2p()

    def sniff(self):
        out = sniffer.main(conn)
        if out:
            for addr in sniffer.p2p_addrs:
                if len(out) > 1:
                    if addr in out[1]:
                        out.insert(0, TAB_2 + 'P2P - обнаружен методом анализирования потоков,')
                elif addr in out[0]:
                    out.insert(0, TAB_2 + 'P2P - обнаружен методом анализирования потоков,')

            for addr in sniffer.p2p_addrs1:
                if len(out) > 1:
                    if addr in out[1]:
                        out.insert(0, TAB_2 + 'P2P - обнаружен методом анализирования портов,')
                elif addr in out[0]:
                    out.insert(0, TAB_2 + 'P2P - обнаружен методом анализирования портов,')

            out.insert(0, str(datetime.now().strftime('%H:%M:%S')) + ":")
            for s in out:
                file.write(s + '\n')
                self.output.insert('end', s + '\n')
        root.after(200, self.sniff)  # сканирование каждые 0.2 сек

    def find_p2p(self):
        sniffer.find_p2p()
        self.p2p_lb.delete(0, 'end')
        for addr in sniffer.p2p_addrs:
            self.p2p_lb.insert('end', addr)
        root.after(15000, self.find_p2p)


conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

# Определение локального IP адреса компьютера
UIP = sniffer.get_local_ip_addr()

# в файл сохраняется последний вывод программы
file = open('out.txt', 'w+')
root = tk.Tk()
root.title("Анализатор сетевого трафика")
menu = Menu(root)
root.mainloop()
file.close()
conn.close()
