# Xuan FENG 520021911147
# 2023/6/3
# CCA2 attack on OAEP RSA
import OAEP
import random
import RSA
from Crypto.Cipher import AES
from binascii import a2b_hex, b2a_hex


class WUP:
    def __init__(self, req="", k=0):
        self.request = req
        self.key = k


class Server:
    def __init__(self):
        self.n, self.e, self.d = RSA.get_keys(1024)
        self.aes = random.randrange(1 << 127, 2 ** 128)

    def generate_history(self):
        padded_request = "this is a history message request"
        while len(padded_request) % 16 != 0:
            padded_request = padded_request + '\0'

        w = WUP()
        cryptor = AES.new(a2b_hex(hex(self.aes)[2:]), AES.MODE_ECB)
        w.request = b2a_hex(cryptor.encrypt((padded_request.encode('utf-8'))))
        w.key = OAEP.Encrypt(hex(self.aes), self.e, self.n)
        return w

    def receive(self, wup):
        # decrypting out AES
        aes = bin(OAEP.Decrypt(wup.key, self.d, self.n))[-128:]
        aes = int(aes, 2)
        string = ""
        for i in hex(aes)[2:]:
            string += i
        align_count = 32 - len(string)
        string = '0' * align_count + string

        decrypter = AES.new(a2b_hex(string), AES.MODE_ECB)
        text = decrypter.decrypt(a2b_hex(wup.request))
        plain_text = b2a_hex(text)
        return plain_text


def main():
    server = Server()
    tmp_wup = server.generate_history()

    current_key = 0

    for ite in range(128, 0, -1):
        test_key = int(current_key >> 1) + (1 << 127)

        padded_request = "attempting to guess"
        while len(padded_request) % 16 != 0:
            padded_request = padded_request + '\0'

        encryptor = AES.new(a2b_hex(hex(test_key)[2:]), AES.MODE_ECB)
        encrypted_request = b2a_hex(encryptor.encrypt(padded_request.encode('utf-8')))

        factor = RSA.fastExpMod(2, (ite - 1) * server.e, server.n)
        encrypted_key = RSA.fastExpMod(tmp_wup.key * factor, 1, server.n)

        # client sends this constructed wup then server checks it
        w = WUP(encrypted_request, encrypted_key)
        re = server.receive(w)
        if re == b2a_hex(bytes(padded_request, encoding='utf-8')):
            current_key = test_key
        else:
            test_key = int(current_key >> 1)
            current_key = test_key

    print("guessed AES_KEY is: ", current_key)
    if current_key == server.aes:
        print("\nSuccess")
    else:
        print("\nFail")


if __name__ == "__main__":
    main()
