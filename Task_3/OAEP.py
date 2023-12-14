# Xuan FENG 520021911147
# 2023/6/3
# OAEP padding on textbook RSA
import hashlib
import random
import RSA


def Encrypt(message, e, n, k0=256, k1=256):
    int_message = int(message, 16)
    r = random.randrange(1 << (k0 - 1), (1 << k0) - 1)
    g_r = hashlib.sha384(hex(r).encode('utf-8'))
    x = int(int_message << k1) ^ int(g_r.hexdigest(), 16)
    h_x = hashlib.sha256(hex(x).encode('utf-8'))
    y = r ^ int(h_x.hexdigest(), 16)
    new_message = (x << k0) + y
    with open("Random_Number.txt", "w") as fd_random_number:
        fd_random_number.write(str(r))
    fd_random_number.close()
    with open("Message_After_Padding.txt", "w") as fd_padded_message:
        fd_padded_message.write(hex(new_message))
    fd_padded_message.close()
    return RSA.fastExpMod(new_message, e, n)


def Decrypt(cipher, d, n, k0=256, k1=256):
    int_cipher = RSA.fastExpMod(cipher, d, n)
    y = int_cipher % (1 << k0)
    x = int_cipher >> k0
    h_x = hashlib.sha256(hex(x).encode('utf-8'))
    r = y ^ int(h_x.hexdigest(), 16)
    g_r = hashlib.sha384(hex(r).encode('utf-8'))
    message = x ^ int(g_r.hexdigest(), 16)
    return message >> k1


def main():
    n, e, d = RSA.get_keys(1024)
    # message = "0xac4d68257dfe"
    with open("Raw_Message.txt", "r") as fd_raw_msg:
        raw_message = fd_raw_msg.read()
    fd_raw_msg.close()

    print("Raw Message: ", raw_message)

    message = hex(int(raw_message.encode('utf-8').hex(), 16))
    cipher = Encrypt(message, e, n)
    print("\nEncrypted Message: ", hex(cipher))
    decrypt = Decrypt(cipher, d, n)
    print("\nDecrypted Message: ", hex(decrypt))
    if hex(decrypt) == message:
        print("\nSuccess")
    else:
        print("\nFail")

    with open("Encrypted_Message.txt", "w") as fd_encrypted_msg:
        fd_encrypted_msg.write(hex(cipher))
    fd_encrypted_msg.close()


if __name__ == "__main__":
    main()
