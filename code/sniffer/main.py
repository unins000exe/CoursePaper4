#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk
import socket
import sniffer
from datetime import datetime
import os
import sys

TAB_2 = '\t * '


class Menu(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.grid(row=0, column=0, sticky=tk.NSEW)
        self.last_time = ''

        self.frame_out = ttk.LabelFrame(self, text='Вывод TCP/UDP трафика')
        self.frame_out.grid(row=0, column=0)

        self.columns = ['1', '2', '3', '4', '5', '6']
        self.output = ttk.Treeview(self, show='headings', columns=self.columns)
        self.output.heading('1', text='Время')
        self.output.heading('2', text='IP источника')
        self.output.heading('3', text='Порт источника')
        self.output.heading('4', text='IP назначения')
        self.output.heading('5', text='Порт назначения')
        self.output.heading('6', text='Протокол')

        self.output.column('1', minwidth=0, width=75)
        self.output.column('2', minwidth=0, width=125)
        self.output.column('3', minwidth=0, width=125)
        self.output.column('4', minwidth=0, width=125)
        self.output.column('5', minwidth=0, width=125)
        self.output.column('6', minwidth=0, width=75)


        # self.output = tk.Text(self.frame_out, width=70, height=35)
        self.output.grid(row=0, column=0, padx=(5, 0), sticky=tk.NW)

        self.scroll_out = ttk.Scrollbar(self.frame_out, command=self.output.yview)
        self.output.config(yscrollcommand=self.scroll_out.set)

        self.frame = ttk.LabelFrame(self, text='Список адресов, взаимодействующих через P2P')
        self.frame.grid(row=0, column=1)

        self.label2 = ttk.Label(self.frame, text='Анализ портов')
        self.label2.grid(row=0, column=0, pady=5, sticky=tk.N)

        self.p2p_lb = tk.Listbox(self.frame, height=20)
        self.p2p_lb.grid(row=1, column=0, sticky=tk.N)

        self.scroll_p2p_lb = ttk.Scrollbar(self.frame, command=self.output.yview)
        self.p2p_lb.config(yscrollcommand=self.scroll_p2p_lb.set)

        self.label3 = ttk.Label(self.frame, text='IP/Port-эвристика')
        self.label3.grid(row=0, column=1, pady=5, sticky=tk.N)

        self.p2p_lb2 = tk.Listbox(self.frame, height=20)
        self.p2p_lb2.grid(row=1, column=1, sticky=tk.N, padx=5)

        self.scroll_p2p_lb2 = ttk.Scrollbar(self.frame, command=self.output.yview)
        self.p2p_lb2.config(yscrollcommand=self.scroll_p2p_lb.set)

        self.label4 = ttk.Label(self.frame, text='TCP/UDP-эвристика')
        self.label4.grid(row=0, column=2, pady=5, sticky=tk.N)

        self.p2p_lb3 = tk.Listbox(self.frame, width=30)
        self.p2p_lb3.grid(row=1, column=2, sticky=tk.N)

        self.scroll_p2p_lb3 = ttk.Scrollbar(self.frame, command=self.output.yview)
        self.p2p_lb3.config(yscrollcommand=self.scroll_p2p_lb.set)

        self.stop_btn = ttk.Button(self, text='Стоп', command=self.stop)
        self.stop_btn.grid(row=1, column=0, pady=(10, 10))

        self.call_sniff()
        self.call_find_p2p()

    def call_sniff(self):
        out = sniffer.sniff(conn, os)
        if out:
            # Вывод времени
            time = str(datetime.now().strftime('%H:%M:%S')) + ":\n"
            if time != self.last_time:
                # self.output.insert('end', time)
                file.write(time)
            self.last_time = time
            ins = [time, out[2], out[4], out[6], out[8], out[1]]
            self.output.insert(parent='', index='end', values=ins)

            # Вывод информации о пакете
            for s in out:
                file.write(s)
                # self.output.insert('end', s)
            file.write('\n')
            # self.output.insert('end', '\n')

        root.after(100, self.call_sniff)  # сканирование каждые 0.1 сек

    def call_find_p2p(self):
        sniffer.find_p2p()
        self.p2p_lb.delete(0, 'end')
        self.p2p_lb2.delete(0, 'end')
        self.p2p_lb3.delete(0, 'end')
        for addr in sniffer.p2p_pairs_p:
            self.p2p_lb.insert('end', addr[0] + ":" + str(addr[1]))
        for addr in sniffer.p2p_pairs_ipp:
            self.p2p_lb2.insert('end', addr[0] + ":" + str(addr[1]))
        for addr in sniffer.p2p_addrs:
            # self.p2p_lb3.insert('end', addrs[0] + " < = > " + addrs[1])
            self.p2p_lb3.insert('end', addr[0] + ":" + str(addr[1]))
        root.after(15000, self.call_find_p2p)

    def stop(self):
        file2.write('Список IP-адресов, взаимодействующих через P2P: \n')
        file2.write('Анализ портов: \n')
        for row in self.p2p_lb.get(0, 'end'):
            file2.write(' * ' + row + '\n')
        file2.write('IP/Port-эвристика: \n')
        for row in self.p2p_lb2.get(0, 'end'):
            file2.write(' * ' + row + '\n')
        file2.write('TCP/UDP-эвристика: \n')
        for row in self.p2p_lb3.get(0, 'end'):
            file2.write(' * ' + row + '\n')
        file2.write('Конец списка. \n')

        root.destroy()


if __name__ == "__main__":
    try:
        if os.name == 'nt':
            os = False
            interface = '192.168.1.100'
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            conn.bind((interface, 0))
            conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            os = True
            interface = 'enp0s3'
            if len(sys.argv) > 1:
                interface = sys.argv[1]
            os.system("ip link set {} promisc on".format(interface))  # ret =
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            conn.bind((interface, 0))
    except socket.error as msg:
        print('Сокет не может быть создан. Код ошибки : ' + str(msg[0]) + ' Сообщение ' + msg[1])
        sys.exit()

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
