import codecs
import hashlib
import os.path

import stdiomask as stdiomask
from Crypto.Cipher import AES


# Question 3
def hash_password(usename, password):
    salt_phrase = f"$2a$12$/{usename}"
    hashed_password = hashlib.pbkdf2_hmac(hash_name='sha512', password=password.encode('utf-8'),
                                          salt=salt_phrase.encode('utf-8'), iterations=100000)
    encoded_hash = codecs.encode(hashed_password, "base64")
    return encoded_hash


# Question 3
def save_credentials():
    user_name = input("Enter your username: ")
    user_password = stdiomask.getpass(prompt="Enter your password: ")

    encoded_hash = hash_password(user_name, user_password)

    with open("crypto_files/credentials.txt", "a") as file:
        file.write(f"{user_name};{encoded_hash}\n")


# Question 3
def check_credentials(arg_name=None, arg_password=None):
    user_name = input("Enter your username: ") if arg_name is None else arg_name
    user_password = stdiomask.getpass(prompt="Enter your password: ") if arg_password is None else arg_password

    encoded_hash = hash_password(user_name, user_password)

    with open("crypto_files/credentials.txt", "r") as file:
        for line in file.readlines():
            if line.split(";")[1].replace("\n", "") == str(encoded_hash):
                print("Welcome!")
                return True
        print("Wrong credentials!")
        return False


# Question 4
def crypt_file_content():
    user_name = input("Enter your username: ")
    password = stdiomask.getpass(prompt="Enter your password: ")
    if not check_credentials(user_name, password):
        return

    file_name = input("Enter the file name: ")
    if not os.path.isfile(f"crypto_files/{file_name}.txt"):
        print("File not found!")
        return

    key = hash_password(user_name, password)[0:32]
    initial_vector = b'o\xa59\x8f\xeaf\xdc\xa477\xa1\xcfg\x87Ip'
    cipher = AES.new(key, AES.MODE_OFB, initial_vector)
    with open(f"crypto_files/{file_name}.txt", "rb") as file:
        plaintext = file.read()
        ciphertext = cipher.encrypt(plaintext)
    with open("crypto_files/secret.enc", "wb") as file:
        file.write(ciphertext)
    print("File encrypted!")


# Question 4
def decrypt_file_content():
    user_name = input("Enter your username: ")
    password = stdiomask.getpass(prompt="Enter your password: ")
    if not check_credentials(user_name, password):
        return

    key = hash_password(user_name, password)[0:32]
    initial_vector = b'o\xa59\x8f\xeaf\xdc\xa477\xa1\xcfg\x87Ip'
    cipher = AES.new(key, AES.MODE_OFB, initial_vector)
    with open("crypto_files/secret.enc", "rb") as file:
        ciphertext = file.read()
        plaintext = cipher.decrypt(ciphertext)
    with open("crypto_files/secret.txt", "wb") as file:
        file.write(plaintext)
    print("File decrypted!")


if __name__ == "__main__":
    # Question 3
    # save_credentials()
    # check_credentials()

    # Question 4
    crypt_file_content()
    decrypt_file_content()
