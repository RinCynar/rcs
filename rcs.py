import sys
import os
import itertools
from arc4 import ARC4

DEFAULT_KEY = "DEF-4164E792FC9AD1C9C866B3D6DCC79A27"
KEYS = [DEFAULT_KEY]
KEY_FILE = ".rcs_keys"

def load_keys():
    global KEYS
    try:
        with open(KEY_FILE, "r") as file:
            KEYS = [DEFAULT_KEY] + [line.strip() for line in file.readlines() if line.strip() != DEFAULT_KEY]
    except FileNotFoundError:
        KEYS = [DEFAULT_KEY]

def save_keys():
    with open(KEY_FILE, "w") as file:
        for key in KEYS:
            if key != DEFAULT_KEY:
                file.write(key + "\n")

def reset_keys():
    global KEYS
    try:
        os.remove(KEY_FILE)
    except FileNotFoundError:
        pass
    KEYS = [DEFAULT_KEY]
    save_keys()
    print("")
    print("Restoring default configuration completed.")
    print("")

def add_key(new_key):
    global KEYS
    if new_key not in KEYS:
        KEYS.append(new_key)
        save_keys()
        print("")
        print(f"Key added: {new_key}")
        print("")
    else:
        print("")
        print(f"Key '{new_key}' already exists.")
        print("")

def delete_key(key_number):
    global KEYS
    try:
        key_number = int(key_number)
        if 0 <= key_number < len(KEYS):
            if KEYS[key_number] == DEFAULT_KEY:
                print("")
                print("Cannot delete the default key.")
                print("")
            else:
                deleted_key = KEYS.pop(key_number)
                save_keys()
                print("")
                print(f"Key deleted: {deleted_key}")
                print("")
        else:
            print("")
            print(f"Invalid key number: {key_number}")
            print("")
    except ValueError:
        print("")
        print(f"Invalid key number: {key_number}")
        print("")

def utf16be_to_bytes(s):
    return s.encode('utf-16be')

def rc4_encrypt(key, plaintext):
    cipher = ARC4(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def rc4_decrypt(key, ciphertext):
    cipher = ARC4(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def bytes_to_hex(b):
    return b.hex().upper()

def hex_to_bytes(h):
    return bytes.fromhex(h)

def choose_key_for_encryption():
    global KEYS
    print("")
    print("Available keys for encryption:")
    print("")
    for i, key in enumerate(KEYS):
        print(f"{i}-{key[:3]}")

    choice = input("Choose a key number (default is 0): ").strip()
    if choice == "":
        return KEYS[0]
    try:
        index = int(choice)
        if 0 <= index < len(KEYS):
            return KEYS[index]
        else:
            print("")
            print("Invalid choice, using default key.")
            print("")
            return KEYS[0]
    except ValueError:
        print("")
        print("Invalid choice, using default key.")
        print("")
        return KEYS[0]

def choose_key_for_decryption():
    global KEYS
    print("")
    print("Trying keys in order:")
    print("")
    for i, key in enumerate(KEYS):
        print(f"{i}-{key[:3]}")

    return KEYS

def interactive_mode():
    print("")
    print("rcs 1.22, a text encryption tool based on RC4 encryption algorithm")
    print("http://rcva.san.tc, Rin' Cynar")
    print("Type 'rcs-help' for usage instructions")
    print("")

    while True:
        try:
            user_input = input("# ").strip()

            if user_input.lower() == 'rcs-exi':
                break

            elif user_input.lower() == 'rcs-help':
                print_help()
                
            elif user_input.startswith('rcs-adk'):
                new_key = user_input.split(' ', 1)[1]
                add_key(new_key)

            elif user_input.startswith('rcs-dek'):
                parts = user_input.split()
                if len(parts) == 2 and parts[0] == 'rcs-dek' and parts[1].startswith('-'):
                    key_number = parts[1][1:]  # Remove the leading '-'
                    delete_key(key_number)
                else:
                    print("")
                    print("Invalid input format for rcs-dek command.")
                    print("Format should be: rcs-dek -<key_number>")
                    print("")

            elif user_input.lower() == 'rcs-res':
                reset_keys()

            elif user_input.lower() == 'rcs-cuk':
                display_keys()

            elif user_input.startswith('rcs-pod'):
                text_to_crack = user_input.split(' ', 1)[1]
                bruteforce_decrypt(text_to_crack)

            elif user_input.startswith('- '):
                decrypt_text(user_input)

            else:
                encrypt_text(user_input)

        except Exception as e:
            print("")
            print(f"Error: {str(e)}")
            print("")

def print_help():
    print("")
    print("Provide the text and press 'Enter', rcs will automatically perform the encryption work, you can choose the key to use for encryption, or just simply press 'Enter' again to use the default options.")
    print("Enter '- <text> -<key_number>' and press Enter, rcs will use the key you specified to decrypt. Of course, you can choose to simply enter '- <text>', rcs will try all the keys that have been saved and return the results.")
    print("Type 'rcs-cuk' to display the currently saved encryption keys")
    print("Type 'rcs-exi' to exit.")
    print("Type 'rcs-res' to reset default configuration.")
    print("Type 'rcs-adk <new-key>' to add a new encryption key.")
    print("Type 'rcs-dek -<key_number>' to delete a specified encryption key.")
    print("Type 'rcs-pod <text>' to attempt brute-force decryption.")
    print("")

def display_keys():
    print("")
    print("Current keys:")
    print("")
    for i, key in enumerate(KEYS):
        print(f"{i}-{key[:3]}x.")
    print("")

def decrypt_text(user_input):
    global KEYS
    parts = user_input.split(' ')
    if len(parts) < 2:
        print("")
        print("Invalid input format.")
        print("")
        return

    text = parts[1]
    key_number = int(parts[2][1:]) if len(parts) > 2 else None

    if key_number is not None:
        if 0 <= key_number < len(KEYS):
            keys_to_try = [KEYS[key_number]]
        else:
            print("")
            print(f"Invalid key number: {key_number}")
            print("")
            return
    else:
        keys_to_try = KEYS

    ciphertext_bytes = hex_to_bytes(text)
    decryption_results = []

    for key in keys_to_try:
        try:
            key_bytes = utf16be_to_bytes(key)
            plaintext_bytes = rc4_decrypt(key_bytes, ciphertext_bytes)
            # Correct decoding of plaintext bytes
            decrypted_text = plaintext_bytes.decode('utf-16be').rstrip('\x00')
            decryption_results.append(f"Decrypted text with key {key[:3]}: {decrypted_text}")
        except Exception as e:
            decryption_results.append(f"Decryption failed with key {key[:3]}")
            continue

    for result in decryption_results:
        print("")
        print(result)
        print("")

def encrypt_text(plaintext):
    key = choose_key_for_encryption()
    key_bytes = utf16be_to_bytes(key)
    plaintext_bytes = utf16be_to_bytes(plaintext)
    ciphertext_bytes = rc4_encrypt(key_bytes, plaintext_bytes)
    ciphertext_hex = bytes_to_hex(ciphertext_bytes)
    print("")
    print(f"Encrypted text: {ciphertext_hex}")
    print("")

def bruteforce_decrypt(ciphertext):
    character_set = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    # 询问用户最小和最大密钥长度
    min_length = int(input("Enter minimum key length: "))
    max_length = int(input("Enter maximum key length: "))

    with open("opt.md", "w") as output_file:
        for length in range(min_length, max_length + 1):
            print(f"Trying keys of length {length}...")
            for attempt in itertools.product(character_set, repeat=length):
                key = ''.join(attempt)
                try:
                    decrypted_text = rc4_decrypt(utf16be_to_bytes(key), hex_to_bytes(ciphertext))
                    # Correct decoding of plaintext bytes
                    decrypted_text = decrypted_text.decode('utf-16be').rstrip('\x00')
                    output_file.write(f"Key: {key}, Decrypted text: {decrypted_text}\n")
                except Exception as e:
                    continue

    print("Bruteforce decryption completed. Results saved in opt.md")

if __name__ == "__main__":
    load_keys() 
    interactive_mode()

