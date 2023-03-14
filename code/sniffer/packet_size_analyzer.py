# file = open('out.txt', 'r')
# dict_sizes = dict()
#
# for line in file:
#     if 'P2P' in line:
#         size = int(line.split()[-4])
#         if size in dict_sizes.keys():
#             dict_sizes[size] += 1
#         else:
#             dict_sizes[size] = 1
#
# sorted_dict = dict()
# sorted_keys = sorted(dict_sizes, key=dict_sizes.get)
#
# for k in sorted_keys[::-1]:
#     sorted_dict[k] = dict_sizes[k]
#     print(k, dict_sizes[k])
#
# s = 0  # всего байт
# for k in dict_sizes:
#     s += k * dict_sizes[k]
#
# print('Всего байт', s)
# print('Среднее значение', s / len(dict_sizes.keys()))

s = '13426974546f7272656e742070726f746f636f6c'
bt = b'\x01\x00\x0cy;L\xc7G\x05q\xa5\xcb\x008\x00\x00\x06\xd6$X\x13BitTorrent protocol\x00\x00\x00\x00\x00\x10\x00\x05\x81\x93}?5\xc5S\xcb\xf7\x1cPX&G!,\x8f\xd6\xd2\x10-UT2210-\xbec\xadR\xec\x1e\x94\xd0\x1aW@\x8b'
sb = bytes.fromhex(s)
print(bt[:50])
