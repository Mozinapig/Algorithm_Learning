import bitarray
from bitarray.util import ba2int, int2ba

class DES:

    # 属性
    def __init__(self):
        # 初始密钥
        self.original_key = None
        # 子密钥
        self.sub_keys = [bitarray.bitarray(48) for _ in range(16)]

    # 子密钥生成方法
    def GenSubKey(self):
        # 置换选择 1
        key_c0 = self.Permute(self.original_key, DES.key_table_c0)
        key_d0 = self.Permute(self.original_key, DES.key_table_d0)

        for i in range(16):
            # 循环左移
            key_c0 = self.RotateLeftInPlace(key_c0, DES.key_rotate_left_table[i])
            key_d0 = self.RotateLeftInPlace(key_d0, DES.key_rotate_left_table[i])
            # 拼接
            concatenated_key = self.Concatenate(key_c0, key_d0)
            # 置换选择 2
            self.sub_keys[i] = self.Permute(concatenated_key, DES.key_table_2)

    # 置换函数
    def Permute(self, original, table):
        permuted = bitarray.bitarray(len(table))
        for i in range(len(table)):
            # 注意 bitarray 是倒过来的
            permuted[i] = original[table[i] - 1]
        return permuted

    # 循环左移
    def RotateLeftInPlace(self, original, length):
        return original[length:] + original[:length]

    # 拼接函数
    def Concatenate(self, left, right):
        return left + right

    # F 函数
    def F(self, original):
        result = bitarray.bitarray(32)
        for i in range(8):
            row = (original[i * 6] << 1) + original[i * 6 + 5]
            column = ba2int(original[i * 6 + 1: i * 6 + 5])
            s_out = DES.s_box[i][row][column]
            result[i * 4:i * 4 + 4] = int2ba(s_out, length=4)
        return result

    # 加密迭代
    def IterEncrypt(self, l, r, round):
        # 选择运算 E
        tmp = self.Permute(r, DES.selection_table_e)
        # 轮密钥加
        tmp ^= self.sub_keys[round]
        # 暂存 l
        tmp_l = l
        l = r
        r = tmp_l ^ self.Permute(self.F(tmp), DES.permutation_table_p)

    # 设置密钥
    def SetKey(self, key):
        self.original_key = key
        self.GenSubKey()

    # 加密函数
    def Encrypt(self, plaintext):
        # 初始 IP 置换
        l = self.Permute(plaintext, DES.ip_table_l0)
        r = self.Permute(plaintext, DES.ip_table_r0)
        # 迭代加密
        for i in range(16):
            self.IterEncrypt(l, r, i)
        # IP 逆置换
        return self.Permute(self.Concatenate(r, l), DES.reverse_ip_table)

    # 解密函数
    def Decrypt(self, ciphertext):
        # 初始 IP 置换
        l = self.Permute(ciphertext, DES.ip_table_l0)
        r = self.Permute(ciphertext, DES.ip_table_r0)
        # 迭代解密
        for i in range(15, -1, -1):
            self.IterEncrypt(l, r, i)
        # IP 逆置换
        return self.Permute(self.Concatenate(r, l), DES.reverse_ip_table)

    # 静态数据（用于置换和S盒）
    key_table_c0 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36
    ]

    key_table_d0 = [
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    key_rotate_left_table = [
        1, 1, 2, 2, 2, 2, 2, 2,
        1, 2, 2, 2, 2, 2, 2, 1
    ]

    key_table_2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]

    ip_table_l0 = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8
    ]

    ip_table_r0 = [
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    selection_table_e = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    s_box = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]


    permutation_table_p = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ]

    reverse_ip_table = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]




if __name__ == "__main__":
    operation = int(input("输入1表示加密，0表示解密: "))
    binary_input = input("请输入二进制字符串: ")

    des = DES()

    # 使用一个固定的密钥，用户可以修改这里的密钥
    key = bitarray.bitarray('1010101010111011000010010001100000100111001101101100110011011101')
    des.SetKey(key)

    # 根据操作选择加密还是解密
    if operation == 1:
        # 加密
        plaintext = bitarray.bitarray(binary_input)
        ciphertext = des.Encrypt(plaintext)
        print("密文:", ciphertext.to01())
    elif operation == 0:
        # 解密
        ciphertext = bitarray.bitarray(binary_input)
        plaintext = des.Decrypt(ciphertext)
        print("明文:", plaintext.to01())
    else:
        print("无效的操作类型，请输入1表示加密，0表示解密。")