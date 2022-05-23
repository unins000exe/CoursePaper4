import socket
import struct
import textwrap

# Отступы для вывода информации
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

# Список пар порт-приложение
LIST_p2p = {6881: 'BitTorrent', 6882: 'BitTorrent', 6883: 'BitTorrent', 6884: 'BitTorrent', 6885: 'BitTorrent',
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
Exceptions = {137, 138, 139, 445, 53, 123, 500, 554, 7070, 6970, 1755, 5000, 5001, 6112, 6868, 6899, 6667, 7000, 7514}

TCP_addrs = set()
UDP_addrs = set()
exceptions_addr = set()
p2p_addrs = set()
p2p_addrs1 = set()
p2p_pairs = set()



def main(conn):
    output = []

    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    output.append('Ethernet кадр:')
    output.append(TAB_1 + 'Назначение: {}, Источник: {}, Протокол: {}'.format(dest_mac, src_mac, eth_proto))

    # IVp4
    if eth_proto == 8:
        (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
        output.append(TAB_1 + 'IPv4 пакет:')
        output.append(TAB_2 + 'Версия: {}, Длина заголовка: {}, TTL: {}'.format(version, header_length, ttl))
        output.append(TAB_2 + 'Протокол: {}, Источник: {}, Назначение: {}'.format(proto, src, target))

        # TCP
        if proto == 6:
            src_port, dest_port, sequence, ack, flag_urg, flag_ack, \
            flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)

            if LIST_p2p.get(src_port, False) or LIST_p2p.get(dest_port, False):
                output.insert(0, "Обнаружен P2P трафик (методом анализирования портов)")

            output.append(TAB_1 + 'TCP сегмент:')
            output.append(TAB_2 + 'Порт источника: {}, Порт назначения: {}'.format(src_port, dest_port))
            output.append(TAB_2 + 'Размер данных (байт): {}'.format(len(data)))

        # UDP
        elif proto == 17:
            src_port, dest_port, length, data = udp_segment(data)
            if LIST_p2p.get(src_port, False) or LIST_p2p.get(dest_port, False):
                output.insert(0, "Обнаружен P2P трафик (методом анализирования портов)")

            output.append(TAB_1 + 'UDP сегмент:')
            output.append(TAB_2 + 'Порт источника: {}, Порт назначения: {}, '
                                  'Длина: {}'.format(src_port, dest_port, length))
            output.append(TAB_2 + 'Размер данных (байт): {}'.format(len(data)))

    return output


def main2(conn):
    output = []
    outline = ''

    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

    # IVp4
    if eth_proto == 8:
        (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

        # TCP
        if proto == 6:
            src_port, dest_port, sequence, ack, flag_urg, flag_ack, \
            flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)

            outline += TAB_1 + 'TCP: ' + src + ':' + str(src_port) + ' -> ' + target + ':' + \
                       str(dest_port) + ', ' + str(len(data)) + ' bytes'
            output.append(outline)

            TCP_addrs.add(src)
            TCP_addrs.add(target)

        # UDP
        elif proto == 17:
            src_port, dest_port, length, data = udp_segment(data)

            outline += TAB_1 + 'UDP: ' + src + ':' + str(src_port) + ' -> ' + target + ':' + \
                       str(dest_port) + ', ' + str(len(data)) + ' bytes'
            output.append(outline)

            UDP_addrs.add(src)
            UDP_addrs.add(target)

        check_intersection()

    return output


def check_intersection():
    inter = TCP_addrs & UDP_addrs
    if inter:
        print(inter)


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


# Распаковка ICMP пакета
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


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


# Форматирование многострочного вывода
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
