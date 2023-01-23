#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk
import socket
import sniffer
from datetime import datetime
import os
import sys
import netifaces as ni
import select

TAB_2 = '\t * '


# TODO: Для интерфейса: кнопка пуск/пауза

class Menu(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.grid(row=0, column=0, sticky=tk.NSEW)
        self.last_time = ''
        self.output_list = []
        self.conn = None
        self.osflag = None

        self.frame_choose_interface = ttk.Frame(self, width=150, height=75)
        self.frame_choose_interface.grid(row=0, column=0)

        self.label_choose_interface = ttk.Label(self.frame_choose_interface,
                                                text='Выберите интерфейс для прослушивания')
        self.label_choose_interface.grid(row=0, column=0)

        self.loi_columns = ['1', '2']
        self.list_of_interfaces = ttk.Treeview(self.frame_choose_interface,
                                               show='headings', columns=self.loi_columns, height=10)
        self.list_of_interfaces.heading('1', text='Интерфейс')
        self.list_of_interfaces.heading('2', text='IP-адрес')
        self.list_of_interfaces.grid(row=1, column=0)

        for inter in inters_ips:
            self.list_of_interfaces.insert(parent='', index='end', values=[inter, inters_ips[inter]])

        self.list_of_interfaces.bind('<Double-1>', self.start)

        self.frame_main = ttk.Frame(self)

        self.columns = ['1', '2', '3', '4', '5', '6', '7']
        self.output = ttk.Treeview(self.frame_main, show='headings', columns=self.columns, height=25)
        self.output.heading('1', text='Время')
        self.output.heading('2', text='Источник')
        self.output.heading('3', text='Назначение')
        self.output.heading('4', text='Порты')
        self.output.heading('5', text='Протокол')
        self.output.heading('6', text='Длина')
        self.output.heading('7', text='Инфо')

        self.output.column('1', minwidth=0, width=55)
        self.output.column('2', minwidth=0, width=100)
        self.output.column('3', minwidth=0, width=100)
        self.output.column('4', minwidth=0, width=125)
        self.output.column('5', minwidth=0, width=70)
        self.output.column('6', minwidth=0, width=50)
        self.output.column('7', minwidth=0, width=150)

        self.scroll_out = ttk.Scrollbar(self.frame_main, command=self.output.yview)
        self.output.config(yscrollcommand=self.scroll_out.set)

        self.frame = ttk.LabelFrame(self.frame_main, text='Список адресов, взаимодействующих через P2P')

        self.label2 = ttk.Label(self.frame, text='Анализ портов')

        self.p2p_lb = tk.Listbox(self.frame, height=20)
        self.p2p_lb.bind('<Double-1>', self.highlight)

        self.scroll_p2p_lb = ttk.Scrollbar(self.frame, command=self.output.yview)
        self.p2p_lb.config(yscrollcommand=self.scroll_p2p_lb.set)

        self.label3 = ttk.Label(self.frame, text='IP/Port-эвристика')

        self.p2p_lb2 = tk.Listbox(self.frame, height=20)

        self.scroll_p2p_lb2 = ttk.Scrollbar(self.frame, command=self.output.yview)
        self.p2p_lb2.config(yscrollcommand=self.scroll_p2p_lb.set)

        self.label4 = ttk.Label(self.frame, text='TCP/UDP-эвристика')

        self.p2p_lb3 = tk.Listbox(self.frame, height=20)

        self.scroll_p2p_lb3 = ttk.Scrollbar(self.frame, command=self.output.yview)
        self.p2p_lb3.config(yscrollcommand=self.scroll_p2p_lb.set)

        self.stop_btn = ttk.Button(self.frame_main, text='Стоп', command=self.stop)

    def start(self, _):
        select = self.list_of_interfaces.selection()[0]
        item = self.list_of_interfaces.item(select)
        interface = item['values'][1]
        self.conn, self.osflag = create_socket(interface)
        self.frame_choose_interface.forget()

        self.frame_main.grid(row=0, column=0)
        self.output.grid(row=0, column=0, padx=(5, 0), sticky=tk.NW)
        self.frame.grid(row=0, column=1)
        self.label2.grid(row=0, column=0, pady=5, sticky=tk.N)
        self.p2p_lb.grid(row=1, column=0, sticky=tk.N)
        self.label3.grid(row=0, column=1, pady=5, sticky=tk.N)
        self.p2p_lb2.grid(row=1, column=1, sticky=tk.N, padx=5)
        self.label4.grid(row=0, column=2, pady=5, sticky=tk.N)
        self.p2p_lb3.grid(row=1, column=2, sticky=tk.N)
        self.stop_btn.grid(row=1, column=0, pady=(10, 10))

        self.call_sniff()
        self.call_find_p2p()

    def highlight(self, _):
        select = self.p2p_lb.curselection()
        ip = self.p2p_lb.get(select)
        print(ip)

        # TODO: должны выделяться строки с выбранным IP

    def call_sniff(self):
        ready = select.select([self.conn], [], [], 0.1)
        if ready[0]:
            out = sniffer.sniff(self.conn, self.osflag)
            if out:
                time = str(datetime.now().strftime('%H:%M:%S'))
                if time != self.last_time:
                    file.write(time)
                self.last_time = time
                ins = [time, out[2], out[6], out[4] + ' -> ' + out[8], out[1], out[10] + ' Б', '']
                self.output_list.append(ins)
                self.output.insert(parent='', index='end', values=ins)

                # Вывод информации о пакете
                for s in out:
                    file.write(s)
                file.write('\n')

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

        self.conn.close()
        file2.close()
        file.close()
        root.destroy()


def create_socket(interface):
    try:
        # Windows needs IP ?
        if os.name == 'nt':
            osflag = False
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            conn.bind((interface, 0))
            conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            conn.setblocking(False)
            # conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Linux needs interface's name
        else:
            osflag = True

            if len(sys.argv) > 1:
                interface = sys.argv[1]
            os.system("ip link set {} promisc on".format(interface))  # ret =
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            conn.bind((interface, 0))
            conn.setblocking(False)
        return conn, osflag
    except socket.error as msg:
        print('Сокет не может быть создан. Код ошибки : ' + str(msg[0]) + ' Сообщение ' + msg[1])
        sys.exit()


# Расшифровка названия интерфейса на Windows
def get_connection_name_from_guid(iface_guids):
    iface_names = ['(unknown)' for i in range(len(iface_guids))]
    reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
    reg_key = wr.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
    for i in range(len(iface_guids)):
        try:
            reg_subkey = wr.OpenKey(reg_key, iface_guids[i] + r'\Connection')
            iface_names[i] = wr.QueryValueEx(reg_subkey, 'Name')[0]
        except FileNotFoundError:
            pass
    return iface_names


#  For Linux
def get_local_interfaces():
    import array
    import struct
    import fcntl
    """ Returns a dictionary of name:ip key value pairs. """
    MAX_BYTES = 4096
    FILL_CHAR = b'\0'
    SIOCGIFCONF = 0x8912
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', MAX_BYTES * FILL_CHAR)
    names_address, names_length = names.buffer_info()
    mutable_byte_buffer = struct.pack('iL', MAX_BYTES, names_address)
    mutated_byte_buffer = fcntl.ioctl(sock.fileno(), SIOCGIFCONF, mutable_byte_buffer)
    max_bytes_out, names_address_out = struct.unpack('iL', mutated_byte_buffer)
    namestr = names.tobytes()
    namestr[:max_bytes_out]
    bytes_out = namestr[:max_bytes_out]
    ip_dict = {}
    for i in range(0, max_bytes_out, 40):
        name = namestr[i: i + 16].split(FILL_CHAR, 1)[0]
        name = name.decode('utf-8')
        ip_bytes = namestr[i+20:i+24]
        full_addr = []
        for netaddr in ip_bytes:
            if isinstance(netaddr, int):
                full_addr.append(str(netaddr))
            elif isinstance(netaddr, str):
                full_addr.append(str(ord(netaddr)))
        # ip_dict[name] = '.'.join(full_addr)
        ip_dict['.'.join(full_addr)] = name # я сделал наоборот, потому что для линукса у меня нужно имя, а не айпи

    return ip_dict


if __name__ == "__main__":
    # Получение списка интерфейсов и их IP

    if os.name == 'nt':
        osflag = False
        import winreg as wr

        interfaces = []
        ips = []

        x = ni.interfaces()
        for interface in x:
            addr = ni.ifaddresses(interface)
            try:
                ip = addr[ni.AF_INET][0]['addr']
                interfaces.append(interface)
                ips.append(ip)
            except:
                pass
        interfaces = get_connection_name_from_guid(interfaces)
        inters_ips = dict(zip(interfaces, ips))

    else:
        osflag = True
        inters_ips = get_local_interfaces()

        # interfaces = ['enp6s0']
        # ips = ['192.168.1.132']


    # print(ni.ifaddresses(_get_default_iface_linux()).setdefault(ni.AF_INET)[0]['addr'])
    # print(ni.interfaces())

    # В файл сохраняется последний вывод программы
    file = open('out.txt', 'w+')
    # Список IP-адресов, взаимодействующих через P2P
    file2 = open('ip_list.txt', 'w+')

    root = tk.Tk()
    root.title("Анализатор сетевого трафика")
    menu = Menu(root)
    root.mainloop()
