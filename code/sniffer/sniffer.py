import socket
import struct

# Отступы для вывода информации
TAB_1 = '\t - '

# Список пар порт-приложение
LIST_P2P = {6881: 'BitTorrent', 6882: 'BitTorrent', 6883: 'BitTorrent',
            6884: 'BitTorrent', 6885: 'BitTorrent', 6886: 'BitTorrent',
            6887: 'BitTorrent', 6888: 'BitTorrent', 6889: 'BitTorrent',
            6969: 'BitTorrent', 411: 'Direct Connect', 412: 'Direct Connect',
            # 2323: 'eDonkey', 3306: 'eDonkey', 4242: 'eDonkey',
            # 4500: 'eDonkey', 4501: 'eDonkey', 4677: 'eDonkey',
            # 4678: 'eDonkey', 4711: 'eDonkey', 4712: 'eDonkey',
            # 7778: 'eDonkey', 1214: 'FastTrack', 1215: 'FastTrack',
            # 1331: 'FastTrack', 1337: 'FastTrack', 1683: 'FastTrack',
            # 4329: 'FastTrack', 5000: 'Yahoo', 5001: 'Yahoo',
            # 5002: 'Yahoo', 5003: 'Yahoo', 5004: 'Yahoo', 5005: 'Yahoo',
            # 5006: 'Yahoo', 5007: 'Yahoo', 5008: 'Yahoo', 5009: 'Yahoo',
            # 5010: 'Yahoo', 5050: 'Yahoo', 5100: 'Yahoo', 5555: 'Napster',
            # 6257: 'Napster', 6666: 'Napster', 6677: 'Napster',
            # 6688: 'Napster', 6699: 'Napster', 6700: 'Napster',
            # 6701: 'Napster', 6346: 'Gnutella', 6347: 'Gnutella', 5190: 'AIM',
            3478: 'Skype', 3479: 'Skype', 3480: 'Skype', 3481: 'Skype',
            4379: 'Steam', 4380: 'Steam (voice chat)', 27014: 'Steam',
            27015: 'Steam', 27016: 'Steam', 27017: 'Steam', 27018: 'Steam',
            27019: 'Steam', 27020: 'Steam', 27021: 'Steam', 27022: 'Steam',
            27023: 'Steam', 27024: 'Steam', 27025: 'Steam', 27026: 'Steam',
            27027: 'Steam', 27028: 'Steam', 27029: 'Steam', 27030: 'Steam',
            899: 'Radmin VPN', 12975: 'Hamachi', 32976: 'Hamachi'}

# Список портов исключений
EXCEPTIONS = {137, 138, 139, 445, 53, 123, 500, 554, 1900, 7070,
              6970, 1755, 5000, 5001, 6112, 6868, 6899, 6667, 7000, 7514,
              20, 21, 3396, 66, 1521, 1526, 1524, 22, 23, 25, 513, 543}

TCP_addrs = set()
UDP_addrs = set()
p2p_addrs_tu = set()  # адреса, взаимодействующие одновременно по TCP и UDP
p2p_pairs_p = set()  # адреса, порт которых входит в список P2P-портов
p2p_pairs_ipp = set()  # адреса, подходящие к IPPort эвристике
rejected = set()  # адреса, не относящиеся к P2P (исключения)
dict_ipport = dict()  # словарь вида (ip+port -> объект класса IPPort)

bittorrent_addrs = set()  # адреса, относящиеся к BitTorrent
bitcoin_addrs = set()  # адреса, относящиеся к Bitcoin
bitcoin_phrases = ['version', 'verack', 'addr', 'inv', 'getdata', 'notfound', 'getblocks',
                   'getheaders', 'tx', 'block', 'headers', 'getaddr', 'mempool', 'checkorder',
                   'submitorder', 'reply', 'ping', 'pong', 'reject', 'filterload', 'filteradd',
                   'filterclear', 'merkleblock', 'alert', 'sendheaders', 'feefilter',
                   'sendcmpct', 'cmpctlblock', 'getblocktxn', 'blocktxn', 'Satoshi']


class IPPort:
    def __init__(self, dst_ip, dst_port):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.IPSet = set()  # IP-адреса источников
        self.PortSet = set()  # Порты источников
        self.srcs = set()
        self.in_packets = dict()
        self.dest_addrs = set()
        self.old_bi = set()
        self.p2p = False  # НЕ ИСПОЛЬЗУЕТСЯ

    def add_sources(self, ip, port):
        self.IPSet.add(ip)
        self.PortSet.add(port)
        self.srcs.add((ip, port))

    def add_packets(self, src_addr, size):
        if src_addr in self.in_packets.keys():
            self.in_packets[src_addr].append(size)
        else:
            self.in_packets[src_addr] = [size]

    def add_out_addrs(self, dest_addr):
        self.dest_addrs.add(dest_addr)

    # Добавление в p2p_addrs1 адресов, которые взаимодействовали с адресами из p2p_addrs_tu
    def add_to_p2p_addrs1(self):
        for ip in self.IPSet:
            if ip not in [ipport[0] for ipport in rejected]:
                # добавляю в p2p_addrs_tu, чтобы относилось к одной эвристике, хотя по сути это p2p_addrs1
                p2p_addrs_tu.add('(*) ' + ip)

    def bt_stats(self):
        # 1
        c = len(self.srcs)
        self.srcs = set()

        # 2
        at = 0
        for addr in self.in_packets:
            packets = self.in_packets[addr]
            pack_size = len(packets)
            if pack_size > 4:
                average_size = 0
                for p in packets:
                    average_size += p
                average_size /= pack_size
                # 1250 или больше поставить?
                if average_size > 1250:
                    at += 1

        # 3
        bi = self.in_packets.keys() & self.dest_addrs

        # 4
        if len(bi) > len(self.old_bi):
            rc = len(bi - self.old_bi)
        else:
            rc = len(self.old_bi - bi)

        self.old_bi = bi

        return c, at, len(bi), rc

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

        if proto == 6 or proto == 17:

            # TCP
            if proto == 6:
                src_port, dest_port, data = tcp_segment(data)

                check_exceptions(src, dest, src_port, dest_port)
                if (src, src_port) not in rejected and (dest, dest_port) not in rejected:
                    TCP_addrs.add((src, dest))

                addition_info = add_info(src, dest, src_port, dest_port)
                output = [src, dest, str(src_port) + ' -> ' + str(dest_port), 'TCP', str(len(data)) + ' Б',
                          addition_info]

            # UDP
            else:
                src_port, dest_port, length, data = udp_segment(data)

                check_exceptions(src, dest, src_port, dest_port)
                if (src, src_port) not in rejected and (dest, dest_port) not in rejected:
                    UDP_addrs.add((src, dest))

                addition_info = add_info(src, dest, src_port, dest_port)
                output = [src, dest, str(src_port) + ' -> ' + str(dest_port), 'UDP', str(len(data)) + ' Б',
                          addition_info]

            add_ipport(dest, dest_port, src, src_port, len(data))
            payload_analysis(src, dest, src_port, dest_port, data)

        return output


# после проверки портов функция
# добавляет к строке вывода информацию для столбца info,
# если адрес p2p и добавляет протокол по возможности
def add_info(src, dest, src_port, dest_port):
    addition_info = ''
    if LIST_P2P.get(src_port, False):
        p2p_pairs_p.add((src, src_port))
        addition_info = 'P2P ' + LIST_P2P[src_port]
    elif LIST_P2P.get(dest_port, False):
        p2p_pairs_p.add((dest, dest_port))
        addition_info = 'P2P ' + LIST_P2P[dest_port]
    elif (src, src_port) in bittorrent_addrs:
        addition_info = 'P2P BitTorrent'
    elif (dest, dest_port) in bittorrent_addrs:
        addition_info = 'P2P BitTorrent'
    elif (src, src_port) in bitcoin_addrs:
        addition_info = 'P2P Bitcoin'
    elif (dest, dest_port) in bitcoin_addrs:
        addition_info = 'P2P Bitcoin'
    return addition_info


def add_ipport(dest, dest_port, src, src_port, size):
    ipport = dest + ':' + str(dest_port)
    if ipport not in dict_ipport:
        x = IPPort(dest, dest_port)
        x.add_sources(src, src_port)
        dict_ipport[ipport] = x
        x.add_packets(src + ':' + str(src_port), size)
    else:
        dict_ipport[ipport].add_sources(src, src_port)
        dict_ipport[ipport].add_packets(src + ':' + str(src_port), size)

    ipport_src = src + ':' + str(src_port)
    if ipport_src in dict_ipport:
        dict_ipport[ipport_src].add_out_addrs(ipport)


# Добавление адресов с портами в список исключений
def check_exceptions(src, dest, src_port, dest_port):
    if src_port in EXCEPTIONS \
            or dest_port in EXCEPTIONS \
            or (src_port == dest_port and src_port < 500):
        rejected.add((src, src_port))
        rejected.add((dest, dest_port))


# Анализ полезной нагрузки пакетов,
def payload_analysis(src, dest, src_port, dest_port, data):
    # Для BitTorrent
    sdata = str(data)
    if len(data) >= 20:
        if 'BitTorrent protocol' in sdata:
            bittorrent_addrs.add((src, src_port))
            bittorrent_addrs.add((dest, dest_port))
        elif src_port == 8333 or dest_port == 8333 or src_port == 8334 or dest_port == 8334:
            # print(sdata)
            for word in bitcoin_phrases:
                if word in sdata:
                    bitcoin_addrs.add((src, src_port))
                    bitcoin_addrs.add((dest, dest_port))
                    break


def find_p2p():
    # 1 Заполнение p2p_addrs адресами, взаимодействующими одновременно по TCP и UDP
    inter = TCP_addrs & UDP_addrs
    for addrs in inter:
        p2p_addrs_tu.add(addrs[0])
        p2p_addrs_tu.add(addrs[1])

    # 2 Заполнение p2p_pairs_ipp адресами, выбранными исходя из check_p2p
    for ipport in dict_ipport:
        ipp = dict_ipport[ipport]

        ip = ipp.dst_ip
        port = ipp.dst_port

        # Добавление адресов, взаимодействующие с адресами из TCP/UDP пар
        if ip in p2p_addrs_tu:
            ipp.add_to_p2p_addrs1()

        compare_dif = 2

        # Если порт из известных p2p портов, то разница должна быть увеличена до 10
        if ipport in p2p_pairs_p:
            compare_dif = 10

        cur_dif = len(ipp.IPSet) - len(ipp.PortSet)
        if len(ipp.IPSet) > 2 and (cur_dif < compare_dif):
            if (ip, port) not in rejected:
                p2p_pairs_ipp.add((ip, port))

        # Если разница больше 10, то, скорее всего, это не p2p и можно добавить в исключения.
        elif cur_dif > 10:
            rejected.add((ip, port))


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
    (src_port, dest_port, _, _, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    # flag_urg = (offset_reserved_flags & 32) >> 5
    # flag_ack = (offset_reserved_flags & 16) >> 5
    # flag_psh = (offset_reserved_flags & 8) >> 5
    # flag_rst = (offset_reserved_flags & 4) >> 5
    # flag_syn = (offset_reserved_flags & 2) >> 5
    # flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, data[offset:]


# Распаковка UDP сегмента
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]
