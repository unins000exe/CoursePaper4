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
        self.last_time = ''

        self.label1 = ttk.Label(self, text='Вывод TCP/UDP трафика')
        self.label1.grid(row=0, column=0, pady=5)

        self.output = tk.Text(self, width=75, height=35)
        self.output.grid(row=1, column=0, padx=(5, 0), sticky=tk.NW)

        self.scroll_out = ttk.Scrollbar(self, command=self.output.yview)
        self.scroll_out.grid(row=1, column=1, padx=(0, 15))
        self.output.config(yscrollcommand=self.scroll_out.set)

        self.label2 = ttk.Label(self, text='Список IP-адресов, взаимодействующих через P2P')
        self.label2.grid(row=0, column=2, pady=5, sticky=tk.N)

        self.p2p_lb = tk.Listbox(self, height=30)
        self.p2p_lb.grid(row=1, column=2, sticky=tk.N)

        self.scroll_p2p_lb = ttk.Scrollbar(self, command=self.output.yview)
        self.scroll_p2p_lb.grid(row=1, column=3, padx=(0, 0))
        self.p2p_lb.config(yscrollcommand=self.scroll_p2p_lb.set)

        self.stop_btn = ttk.Button(self, text='Стоп', command=self.stop)
        self.stop_btn.grid(row=2, column=2, pady=(0, 10))

        self.sniff()
        self.find_p2p()

    def sniff(self):
        out = sniffer.main(conn)
        if out:
            # Вывод времени
            time = str(datetime.now().strftime('%H:%M:%S')) + ":\n"
            if time != self.last_time:
                self.output.insert('end', time)
            self.last_time = time

            # Вывод метода, которым был обнаружен P2P
            if out[2] in sniffer.p2p_addrs_p or out[6] in sniffer.p2p_addrs_p:
                if out[2] in sniffer.p2p_addrs1.union(sniffer.p2p_addrs) or \
                        out[6] in sniffer.p2p_addrs1.union(sniffer.p2p_addrs):
                    self.output.insert('end', TAB_2 + 'P2P - обнаружен методом анализирования портов и потоков,\n')
                else:
                    self.output.insert('end', TAB_2 + 'P2P - обнаружен методом анализирования портов,\n')

            elif out[2] in sniffer.p2p_addrs1.union(sniffer.p2p_addrs) or \
                    out[6] in sniffer.p2p_addrs1.union(sniffer.p2p_addrs):
                self.output.insert('end', TAB_2 + 'P2P - обнаружен методом анализирования потоков\n')

            # Вывод информации о пакете
            for s in out:
                file.write(s)
                self.output.insert('end', s)
            file.write('\n')
            self.output.insert('end', '\n')

        root.after(100, self.sniff)  # сканирование каждые 0.1 сек

    def find_p2p(self):
        sniffer.find_p2p()
        self.p2p_lb.delete(0, 'end')
        for addr in sniffer.p2p_addrs_res:
            self.p2p_lb.insert('end', addr)
        root.after(15000, self.find_p2p)  # обнаружение p2p методом анализирования потоков запускается каждые 15 секунд

    def stop(self):
        file2.write('Список IP-адресов, взаимодействующих через P2P: \n')
        for ip in self.p2p_lb.get(0, 'end'):
            file2.write(' * ' + ip + '\n')
        file2.write('Конец списка. \n')

        root.destroy()


conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

# В файл сохраняется последний вывод программы
file = open('out.txt', 'w+')
# Список IP-адресов, взаимодействующих через P2P
file2 = open('ip_list.txt', 'w+')

root = tk.Tk()
root.title("Анализатор сетевого трафика")
menu = Menu(root)
root.mainloop()
file2.close()
file.close()
conn.close()
