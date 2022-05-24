import socket
import struct
import textwrap

# Отступы для вывода информации
TAB_1 = '\t - '

# Список пар порт-приложение
LIST_P2P = {6881: 'BitTorrent', 6882: 'BitTorrent', 6883: 'BitTorrent', 6884: 'BitTorrent', 6885: 'BitTorrent',
            6886: 'BitTorrent', 6887: 'BitTorrent', 6888: 'BitTorrent', 6889: 'BitTorrent', 6969: 'BitTorrent',
            411: 'Direct Connect', 412: 'Direct Connect', 2323: 'eDonkey', 3306: 'eDonkey', 4242: 'eDonkey',
            4500: 'eDonkey', 4501: 'eDonkey', 4677: 'eDonkey', 4678: 'eDonkey', 4711: 'eDonkey', 4712: 'eDonkey',
            7778: 'eDonkey', 1214: 'FastTrack', 1215: 'FastTrack', 1331: 'FastTrack', 1337: 'FastTrack',
            1683: 'FastTrack', 4329: 'FastTrack', 5000: 'Yahoo', 5001: 'Yahoo', 5002: 'Yahoo', 5003: 'Yahoo',
            5004: 'Yahoo', 5005: 'Yahoo', 5006: 'Yahoo', 5007: 'Yahoo', 5008: 'Yahoo', 5009: 'Yahoo',
            5010: 'Yahoo', 5050: 'Yahoo', 5100: 'Yahoo', 5555: 'Napster', 6257: 'Napster', 6666: 'Napster',
            6677: 'Napster', 6688: 'Napster', 6699: 'Napster', 6700: 'Napster', 6701: 'Napster',
            6346: 'Gnutella', 6347: 'Gnutella', 5190: 'AIM', 3478: 'Skype / Steam (voice chat)',
            4379: 'Steam (voice chat)', 4380: 'Steam (voice chat)', 4899: 'Radmin VPN', 12975: 'Hamachi',
            32976: 'Hamachi', 3479: 'Skype', 3480: 'Skype', 3481: 'Skype'}

# Список портов исключений
EXCEPTIONS = {137, 138, 139, 445, 53, 123, 500, 554, 7070, 6970, 1755, 5000, 5001, 6112, 6868, 6899, 6667, 7000, 7514}

TCP_addrs = set()
UDP_addrs = set()
p2p_addrs = set()  # IP-адреса, отнесённые к P2P методом анализирования потоков
p2p_addrs1 = set()  # IP-адреса, отнесённые к P2P методом анализирования портов
rejected = set()  # адреса, не относящиеся к P2P
UIP = ''  # локальный IP-адрес

dict_ipport = dict()  # словарь вида (ip+port -> объект класса IPPort)


class IPPort:
    def __init__(self, dst_ip, dst_port):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.IPSet = set()
        self.PortSet = set()

    def add(self, ip, port):
        self.IPSet.add(ip)
        self.PortSet.add(port)

    def check_p2p(self):
        return len(self.IPSet) > 2 and (len(self.IPSet) - len(self.PortSet) < 2)


def main(conn):
    output = []
    outline = ''

    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

    # IPv4
    if eth_proto == 8:
        (version, header_length, ttl, proto, src, dest, data) = ipv4_packet(data)

        # TCP
        if proto == 6:
            src_port, dest_port, sequence, ack, flag_urg, flag_ack, \
            flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)

            outline += TAB_1 + 'TCP: ' + src + ':' + str(src_port) + ' -> ' + dest + ':' + \
                       str(dest_port) + ', ' + str(len(data)) + ' bytes'
            output.append(outline)

            save(src, dest, src_port, dest_port)
            check_ports(src, dest, src_port, dest_port)

        # UDP
        elif proto == 17:
            src_port, dest_port, length, data = udp_segment(data)

            outline += TAB_1 + 'UDP: ' + src + ':' + str(src_port) + ' -> ' + dest + ':' + \
                       str(dest_port) + ', ' + str(len(data)) + ' bytes'
            output.append(outline)

            check_ports(src, dest, src_port, dest_port)
            save(src, dest, src_port, dest_port)

        check_intersection()

    return output


def get_local_ip_addr():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    global UIP
    UIP = s.getsockname()[0]
    s.close()
    return UIP


def save(src, dest, src_port, dest_port):
    TCP_addrs.add(src)
    TCP_addrs.add(dest)
    UDP_addrs.add(src)
    UDP_addrs.add(dest)
    check_exceptions(src, src_port)
    check_exceptions(dest, dest_port)
    add_ipport(dest, dest_port, src, src_port)


def check_ports(src, dest, src_port, dest_port):
    if LIST_P2P.get(src_port, False) or LIST_P2P.get(dest_port, False):
        if src != UIP:
            p2p_addrs1.add(src)
        else:
            p2p_addrs1.add(dest)

def add_ipport(dest, dest_port, src, src_port):
    ipport = dest + str(dest_port)
    if ipport not in dict_ipport:
        x = IPPort(dest, dest_port)
        x.add(src, src_port)
        dict_ipport[ipport] = x
    else:
        dict_ipport[ipport].add(src, src_port)


def check_intersection():
    inter = TCP_addrs & UDP_addrs
    return inter


def check_exceptions(addr, port):
    if addr != UIP and port in EXCEPTIONS:
        rejected.add(addr)
        return False
    else:
        return True


def find_p2p():
    # 1 Заполнение p2p_addrs адресами, взаимодействующими одновременно по TCP и UDP с учётом исключений
    inter = check_intersection()
    for addr in inter:
        if addr not in rejected and addr != UIP:
            p2p_addrs.add(addr)

    # 2 Заполнение p2p_addrs адресами, выбранными исходя из check_p2p с учётом исключений
    for ipport in dict_ipport:
        ipp = dict_ipport[ipport]
        ip = ipp.dst_ip
        port = ipp.dst_port
        if ipp.check_p2p() and check_exceptions(ip, port) and ip != UIP:
            p2p_addrs.add(ip)

    return p2p_addrs


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
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Распаковка UDP сегмента
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]
