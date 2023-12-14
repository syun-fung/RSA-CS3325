# Xuan FENG 520021911147
# 2023/6/3
# CCA2 Attack Simulation
from Crypto.Cipher import AES
import random
from binascii import a2b_hex, b2a_hex
import RSA


class WUP:
    def __init__(self, req="", k=""):
        self.request = req
        self.key = k


class Server:
    def __init__(self):
        self.n, self.e, self.d = RSA.get_keys(1024)
        self.aes = random.randrange(1 << 127, 2 ** 128)
        with open("AES_Key.txt", "w") as fd_AES_key:
            fd_AES_key.write(hex(self.aes))
        fd_AES_key.close()

    def generate_history(self):
        request = "this is a history message request"
        with open("WUP_Request.txt", "w") as fd_WUP_request:
            fd_WUP_request.write(hex(int(request.encode('utf-8').hex(), 16)))
        fd_WUP_request.close()

        while len(request) % 16 != 0:
            request = request + '\0'

        w = WUP()
        cryptor = AES.new(a2b_hex(hex(self.aes)[2:]), AES.MODE_ECB)
        w.request = b2a_hex(cryptor.encrypt(request.encode('utf-8')))
        w.key = RSA.fastExpMod(self.aes, self.e, self.n)
        with open("History_Message.txt", "w") as fd_history_message:
            fd_history_message.write(str(w.request))
            fd_history_message.write("\n")
            fd_history_message.write(str(w.key))
        fd_history_message.close()
        with open("AES_Encrypted_WUP.txt", "w") as fd_AES_Enc_WUP:
            fd_AES_Enc_WUP.write(str(w.request))
        fd_AES_Enc_WUP.close()
        return w

    def receive(self, wup):
        # decrypting out AES
        aes = bin(RSA.fastExpMod(wup.key, self.d, self.n))[-128:]
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
        encrypted_request = str(b2a_hex(encryptor.encrypt(padded_request.encode('utf-8'))), 'utf-8')

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

    decrypter = AES.new(a2b_hex(hex(current_key)[2:]), AES.MODE_ECB)
    text = str(decrypter.decrypt(a2b_hex(tmp_wup.request)), encoding='utf-8')
    plain_text = text.rstrip('\0')
    print("History information: ", plain_text)
    print("AES_KEY is: ", current_key)
    if current_key == server.aes:
        print("Success")
    else:
        print("Fail")


if __name__ == "__main__":
    main()
