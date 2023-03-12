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
sb = bytes.fromhex(s)
print(sb)
