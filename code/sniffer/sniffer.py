import socket
import struct

# Отступы для вывода информации
TAB_1 = '\t - '

# Список пар порт-приложение
LIST_P2P = {6881: 'BitTorrent', 6882: 'BitTorrent', 6883: 'BitTorrent',
            6884: 'BitTorrent', 6885: 'BitTorrent', 6886: 'BitTorrent',
            6887: 'BitTorrent', 6888: 'BitTorrent', 6889: 'BitTorrent',
            6969: 'BitTorrent', 411: 'Direct Connect', 412: 'Direct Connect',
            2323: 'eDonkey', 3306: 'eDonkey', 4242: 'eDonkey',
            4500: 'eDonkey', 4501: 'eDonkey', 4677: 'eDonkey',
            4678: 'eDonkey', 4711: 'eDonkey', 4712: 'eDonkey',
            7778: 'eDonkey', 1214: 'FastTrack', 1215: 'FastTrack',
            1331: 'FastTrack', 1337: 'FastTrack', 1683: 'FastTrack',
            4329: 'FastTrack', 5000: 'Yahoo', 5001: 'Yahoo',
            5002: 'Yahoo', 5003: 'Yahoo', 5004: 'Yahoo', 5005: 'Yahoo',
            5006: 'Yahoo', 5007: 'Yahoo', 5008: 'Yahoo', 5009: 'Yahoo',
            5010: 'Yahoo', 5050: 'Yahoo', 5100: 'Yahoo', 5555: 'Napster',
            6257: 'Napster', 6666: 'Napster', 6677: 'Napster',
            6688: 'Napster', 6699: 'Napster', 6700: 'Napster',
            6701: 'Napster', 6346: 'Gnutella', 6347: 'Gnutella', 5190: 'AIM',
            3478: 'Skype / Steam (voice chat)', 4379: 'Steam (voice chat)',
            4380: 'Steam (voice chat)', 4899: 'Radmin VPN', 12975: 'Hamachi',
            32976: 'Hamachi', 3479: 'Skype', 3480: 'Skype', 3481: 'Skype'}

# Список портов исключений
EXCEPTIONS = {137, 138, 139, 445, 53, 123, 500, 554, 1900, 7070,
              6970, 1755, 5000, 5001, 6112, 6868, 6899, 6667, 7000, 7514,
              20, 21, 3396, 66, 1521, 1526, 1524, 22, 23, 513, 543}

TCP_addrs = set()
UDP_addrs = set()
p2p_addrs = set()  # адреса, взаимодействующие одновременно по TCP и UDP
p2p_addrs1 = set()  # адреса, которые взаимодействовали с адресами из p2p_addrs1
p2p_pairs_p = set()  # адреса, порт которых входит в список P2P-портов
p2p_pairs_ipp = set()  # адреса, подходящие к IPPort эвристике
rejected = set()  # адреса, не относящиеся к P2P (исключения)
dict_ipport = dict()  # словарь вида (ip+port -> объект класса IPPort)


class IPPort:
    def __init__(self, dst_ip, dst_port):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.IPSet = set()  # IP-адреса источников
        self.PortSet = set()  # Порты источников
        self.p2p = False

    def add_sources(self, ip, port):
        self.IPSet.add(ip)
        self.PortSet.add(port)

    # Добавление в p2p_addrs1 адресов, которые взаимодействовали с адресами из p2p_addrs
    def add_to_p2p_addrs1(self):
        for addr in p2p_addrs:
            if addr[0] in self.IPSet and addr not in rejected:
                # добавляю в p2p_addrs, чтобы относилось к одной эвристике, хотя по сути это p2p_addrs1
                p2p_addrs.add(addr + ' (*)')

    # TODO: сделать один нормальный метод в классе, убрать find_p2p, не знаю
    # Проверка IP/Port-эвристики
    def check_p2p(self):
        dif = 2
        # Если порт из списка исключений, то разница между IPSet и PortSet должна быть увеличена до 10
        if self.dst_port in EXCEPTIONS:
            dif = 10
        if (self.dst_ip, self.dst_port) not in rejected:
            self.p2p = len(self.IPSet) > 2 and (len(self.IPSet) - len(self.PortSet) < dif)
        else:
            self.p2p = False
        return self.p2p


def sniff(conn, os):
    output = ''
    data, addr = conn.recvfrom(65536)
    if os:
        dest_mac, src_mac, eth_proto, data = ethernet_frame(data)
    else:
        eth_proto = 8

    # IPv4
    if eth_proto == 8:
        version, header_length, ttl, proto, src, dest, data = ipv4_packet(data)

        # TCP
        if proto == 6:
            src_port, dest_port, sequence, ack, flag_urg, flag_ack, \
            flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)

            output = [TAB_1, 'TCP ', src, ':', str(src_port), ' -> ', dest, ':',
                      str(dest_port), ', ', str(len(data)), ' Б']

            check_exceptions(src, dest, src_port, dest_port)
            if (src, src_port) not in rejected:
                TCP_addrs.add((src, src_port))
            if (dest, dest_port) not in rejected:
                TCP_addrs.add((dest, dest_port))
            add_ipport(dest, dest_port, src, src_port)
            check_ports(src, dest, src_port, dest_port)

        # UDP
        elif proto == 17:
            src_port, dest_port, length, data = udp_segment(data)

            output = [TAB_1, 'UDP ', src, ':', str(src_port), ' -> ', dest, ':',
                      str(dest_port), ', ', str(len(data)), ' Б']

            if (src, src_port) not in rejected:
                UDP_addrs.add((src, src_port))
            if (dest, dest_port) not in rejected:
                UDP_addrs.add((dest, dest_port))
            check_exceptions(src, dest, src_port, dest_port)
            add_ipport(dest, dest_port, src, src_port)
            check_ports(src, dest, src_port, dest_port)

    return output


# TODO: по-моему не все записи замечает
def check_ports(src, dest, src_port, dest_port):
    if LIST_P2P.get(src_port, False):
        p2p_pairs_p.add((src, src_port))
    elif LIST_P2P.get(dest_port, False):
        p2p_pairs_p.add((dest, dest_port))


def add_ipport(dest, dest_port, src, src_port):
    ipport = dest + ':' + str(dest_port)
    if ipport not in dict_ipport:
        x = IPPort(dest, dest_port)
        x.add_sources(src, src_port)
        dict_ipport[ipport] = x
    else:
        dict_ipport[ipport].add_sources(src, src_port)


# Добавление адресов с портами в список исключений
def check_exceptions(src, dest, src_port, dest_port):
    if src_port in EXCEPTIONS \
            or dest_port in EXCEPTIONS \
            or (src_port == dest_port and src_port < 500):
        rejected.add((src, src_port))
        rejected.add((dest, dest_port))


def find_p2p():
    print('Исключения', rejected)
    # 1 Заполнение p2p_addrs адресами, взаимодействующими одновременно по TCP и UDP
    inter = TCP_addrs & UDP_addrs
    for addr in inter:
        p2p_addrs.add(addr)

    # 2 Заполнение p2p_pairs_ipp адресами, выбранными исходя из check_p2p
    for ipport in dict_ipport:
        ipp = dict_ipport[ipport]
        ipp.add_to_p2p_addrs1()
        ip = ipp.dst_ip
        port = ipp.dst_port
        dif = 2
        # Если порт из списка исключений, то разница между IPSet и PortSet должна быть увеличена до 10
        if port in EXCEPTIONS:
            dif = 10
        if (ip, port) not in rejected:
            ipp.p2p = len(ipp.IPSet) > 2 and (len(ipp.IPSet) - len(ipp.PortSet) < dif)
        else:
            ipp.p2p = False
        if ipp.p2p and (ip, port) not in rejected:
            p2p_pairs_ipp.add((ip, port))


# Распаковка ethernet кадра
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Форматирование MAC-адреса
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# Распаковка IPv4 пакета
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Форматирование IP-адреса
def ipv4(addr):
    return '.'.join(map(str, addr))


# Распаковка TCP сегмента
def tcp_segment(data):
    (src_port, dest_port, sequence, ack, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 5
    flag_psh = (offset_reserved_flags & 8) >> 5
    flag_rst = (offset_reserved_flags & 4) >> 5
    flag_syn = (offset_reserved_flags & 2) >> 5
    flag_fin = offset_reserved_flags & 1
    return str(src_port), str(dest_port), sequence, ack, \
           flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# TODO: мб всё же в виде строки возвращать
# Распаковка UDP сегмента
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]
