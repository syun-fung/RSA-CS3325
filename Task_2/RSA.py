# Xuan FENG 520021911147
# 2023/6/3
# textbook RSA implementation
import random
import binascii


# (a ^ b) % c
# using power decomposition to calculate faster
def fastExpMod(a, b, c):
    result = 1
    while b != 0:
        if (b & 1) == 1:
            result = (result * a) % c
        b >>= 1
        a = (a * a) % c
    return result


# to get a prime number
def get_prime(size=1024):
    while True:
        num = random.randrange(2 ** (size - 1), 2 ** size)
        if is_prime(num):
            return num


# rabin_miller algorithm, checking if a large integer is prime
def rabin_miller(num):
    # Write num-1 as 2^r * d
    r, s = 0, num - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(5):
        a = random.randint(2, num - 2)
        x = pow(a, s, num)

        if x == 1 or x == num - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, num)
            if x == num - 1:
                break
        else:
            return False

    return True


# check if a number is prime
def is_prime(num):
    if num < 2:
        return False

    # for small numbers
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
                    103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
                    211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
                    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
                    449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577,
                    587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
                    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
                    853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
                    991, 997]
    if num in small_primes:
        return True

    for prime in small_primes:
        if num % prime == 0:
            return False

    return rabin_miller(num)


# calculate gcd of two numbers
def gcd(a, b):
    remainder = a % b
    while remainder != 0:
        a = b
        b = remainder
        remainder = a % b
    return b


# extended euclid algorithm for (a ^ -1) mod b
def ext_euclid(a, b):
    if b == 0:
        return 1, 0
    else:
        k = a // b
        remainder = a % b
        x1, y1 = ext_euclid(b, remainder)
        x, y = y1, x1 - k * y1
    return x, y


def get_keys(size=1024):
    e = 65537
    while True:
        l1 = size // 2
        l2 = size - l1
        flag = 0
        while True:
            p = get_prime(l1)
            q = get_prime(l2)
            n = p * q
            x = p * q
            k = 0
            while x != 0:
                x >>= 1
                k = k + 1
            if k > size and flag == 0:
                l1 -= 1
                flag = 1
            if k > size and flag == 1:
                l2 -= 1
                flag = 0
            if k == size:
                break
        euler = (p - 1) * (q - 1)
        if gcd(e, euler) == 1:
            x, y = ext_euclid(e, euler)
            d = x % euler
            with open("RSA_Modular.txt", "w") as fd1:
                fd1.write(str(n))
            fd1.close()
            with open("RSA_p.txt", "w") as fd2:
                fd2.write(str(p))
            fd2.close()
            with open("RSA_q.txt", "w") as fd3:
                fd3.write(str(q))
            fd3.close()
            with open("RSA_Secret_Key.txt", "w") as pubK:
                pubK.write(str(e))
            pubK.close()
            with open("RSA_Private_Key.txt", "w") as prvK:
                prvK.write(str(d))
            prvK.close()
            break
    return n, e, d


def main():
    size = eval(input("key size: "))
    n, e, d = get_keys(size)

    # msg_str = "hello world!"
    with open("Raw_Message.txt", "r") as raw_message:
        msg_str = raw_message.read()
    raw_message.close()
    print("\nraw_message = ", msg_str)

    msg_str = bytes(msg_str, encoding='utf-8')
    msg_plain = int(binascii.b2a_hex(msg_str), 16)
    cipher = fastExpMod(msg_plain, e, n)
    with open("Encrypted_Message.txt", "w") as encrypted_msg:
        encrypted_msg.write(hex(cipher))
    encrypted_msg.close()
    print("\ncipher =  ", cipher)

    decipher = fastExpMod(cipher, d, n)
    decipher_int = binascii.a2b_hex(hex(decipher)[2:])
    print("\ndecipher = ", str(decipher_int, encoding='utf-8'))


if __name__ == "__main__":
    main()
