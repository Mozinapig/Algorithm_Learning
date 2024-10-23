class ZuChongzhiStreamCipher:
    def __init__(self, key, iv):
        """
        初始化祖冲之序列密码算法
        :param key: 密钥，假设为一个二进制字符串
        :param iv: 初始向量，作为 LFSR 的种子
        """
        self.key = key
        self.iv = iv

    def initialize_lfsr(self, iv):
        """
        初始化 LFSR 状态
        :param iv: 初始向量
        :return: LFSR 的初始状态
        """
        return [int(bit) for bit in iv]

    def lfsr_step(self, lfsr_state):
        """
        生成 LFSR 的下一个比特
        :param lfsr_state: 当前 LFSR 状态
        :return: 下一个比特和更新后的状态
        """
        new_bit = lfsr_state[0] ^ lfsr_state[2] ^ lfsr_state[3] ^ lfsr_state[5]
        new_state = lfsr_state[1:] + [new_bit]
        return new_bit, new_state

    def generate_keystream(self, iv, length):
        """
        生成密钥流
        :param iv: 初始向量
        :param length: 需要的密钥流长度
        :return: 密钥流，作为二进制字符串
        """
        lfsr_state = self.initialize_lfsr(iv)
        keystream = []
        for _ in range(length):
            new_bit, lfsr_state = self.lfsr_step(lfsr_state)
            keystream.append(new_bit)
        return keystream

    def encrypt(self, plaintext):
        """
        加密函数
        :param plaintext: 明文，作为二进制字符串
        :return: 密文，作为二进制字符串
        """
        keystream = self.generate_keystream(self.iv, len(plaintext))
        ciphertext = [int(pt_bit) ^ ks_bit for pt_bit, ks_bit in zip(plaintext, keystream)]
        return ''.join(map(str, ciphertext))

    def decrypt(self, ciphertext):
        """
        解密函数，和加密是同样的操作
        :param ciphertext: 密文，作为二进制字符串
        :return: 解密后的明文，作为二进制字符串
        """
        keystream = self.generate_keystream(self.iv, len(ciphertext))
        decrypted = [int(ct_bit) ^ ks_bit for ct_bit, ks_bit in zip(ciphertext, keystream)]
        return ''.join(map(str, decrypted))  # 返回解密后的明文

if __name__ == "__main__":
    # 示例用法：
    key = "110101"  # 假设密钥为二进制字符串（未使用）
    iv = "101010"  # 假设初始向量为二进制字符串
    cipher = ZuChongzhiStreamCipher(key, iv)

    plaintext = "1101001100010001"  # 需要加密的明文
    print(f"明文: {plaintext}")

    # 加密
    ciphertext = cipher.encrypt(plaintext)
    print(f"密文: {ciphertext}")

    # 解密
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密后: {decrypted}")