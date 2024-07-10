import sys
import os
import itertools
import requests
from arc4 import ARC4

DEFAULT_KEY = "DEF-4164E792FC9AD1C9C866B3D6DCC79A27"
KEYS = [DEFAULT_KEY]
RCS_FOLDER = ".rcs"
KEY_FILE_TEMPLATE = os.path.join(RCS_FOLDER, "{}.rcs_keys")
HISTORY_FILE_TEMPLATE = os.path.join(RCS_FOLDER, "{}.rcs_hst")
OPT_FILE = "rcs_opt.md"
RCS_VER = 1.71
DOWNLOAD_LINK = "https://rcva.san.tc/assets/file/rcs.py"
UPDATE_URL = "http://rcs.rcva.san.tc/"

username = ""


def print_message(message):
    print("\n" + message + "\n")


def get_input(prompt, default=None):
    user_input = input(prompt).strip()
    return user_input if user_input else default


def load_keys():
    global KEYS, username
    key_file = KEY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    try:
        with open(key_file, "rb") as file:
            encrypted_keys = file.readlines()
            for line in encrypted_keys:
                decrypted_line = rc4_decrypt(
                    username.encode("utf-16"), line.strip()
                ).decode("utf-16")
                if decrypted_line.strip() != DEFAULT_KEY:
                    KEYS.append(decrypted_line.strip())
    except FileNotFoundError:
        KEYS = [DEFAULT_KEY]


def save_keys():
    key_file = KEY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    with open(key_file, "wb") as file:
        encrypted_username = (
            rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")) + b"\n"
        )
        file.write(encrypted_username)
        for key in KEYS:
            if key != DEFAULT_KEY:
                encrypted_key = (
                    rc4_encrypt(username.encode("utf-16"), key.encode("utf-16")) + b"\n"
                )
                file.write(encrypted_key)


def reset():
    global KEYS
    try:
        os.remove(
            HISTORY_FILE_TEMPLATE.format(
                bytes_to_hex(
                    rc4_encrypt(username.encode("utf-16"), username.encode("utf-16"))
                )
            )
        )
        os.remove(
            KEY_FILE_TEMPLATE.format(
                bytes_to_hex(
                    rc4_encrypt(username.encode("utf-16"), username.encode("utf-16"))
                )
            )
        )
    except FileNotFoundError:
        pass
    KEYS = [DEFAULT_KEY]
    save_keys()
    print_message("卡芙卡/言靈 聽我說：你的腦袋裡現在一片混沌.你不清楚你是誰，為什麼在這兒，接下來要做什麼；你覺得我很熟悉，卻不清楚該不該信任我- -\n--但這都不重要.重要的是我要走了，要把你一個人丟在這個太空站裡.所以從現在開始，你不用再思考過去，也不用再懷疑自己.")

def add_key(new_key):
    global KEYS
    if new_key not in KEYS:
        KEYS.append(new_key)
        save_keys()
        print_message(f"浮黎 新的「記憶」已記錄 {new_key}.")
    else:
        print_message(f"浮黎 「記憶」 '{new_key}' 已經存在.")


def delete_key(key_number):
    global KEYS
    try:
        key_number = int(key_number)
        if 0 <= key_number < len(KEYS):
            if KEYS[key_number] == DEFAULT_KEY:
                print_message("「我偷偷拿走金色的砝碼，為激起的漣漪洋洋得意；祂總能看穿我的詭計，星星又將遊碼歸零。」\n--阿德里安-斯賓塞-史密斯，《有關於星空的寓言集》")
            else:
                deleted_key = KEYS.pop(key_number)
                save_keys()
                print_message(f"流螢/薩姆 我將，點燃「星海」！ {deleted_key}")
        else:
            print_message(f"嘲諷中無法選取該目標： {key_number}")
    except ValueError:
        print_message(f"嘲諷中無法選取該目標： {key_number}")


def utf16_to_bytes(s):
    return s.encode("utf-16")


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
    print_message("模擬宇宙下載器：")
    for i, key in enumerate(KEYS):
        print(f"{i}-{key[:3]}")

    choice = get_input("維里塔斯-拉帝奧 切勿心急，想明白再做決定. ", "0")
    try:
        index = int(choice)
        if 0 <= index < len(KEYS):
            return KEYS[index]
        else:
            raise ValueError
    except ValueError:
        print_message("維里塔斯-拉帝奧 很苦惱的樣子啊,遇到麻煩了?既然如此--你自己想辦法吧.")
        return KEYS[0]


def choose_key_for_decryption():
    global KEYS
    print_message("姬子 人類的求索之心可是永無止境的.")
    for i, key in enumerate(KEYS):
        print(f"{i}-{key[:3]}")
    return KEYS


def save_history(record):
    encrypted_record = rc4_encrypt(username.encode("utf-16"), record.encode("utf-16"))
    history_file = HISTORY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    with open(history_file, "ab") as file:
        file.write(encrypted_record + b"\n")


def display_history():
    history_file = HISTORY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    try:
        with open(history_file, "rb") as file:
            history = file.readlines()
            if not history:
                print_message("黃泉 切勿回頭，來處無路可走.")
            else:
                for line in history:
                    try:
                        decrypted_line = rc4_decrypt(
                            username.encode("utf-16"), line.strip()
                        )
                        print(decrypted_line.decode("utf-16").rstrip("\x00"))
                        print("")
                    except Exception as e:
                        print_message(f"維里塔斯-拉帝奧 很苦惱的樣子啊,遇到麻煩了?既然如此--你自己想辦法吧. {str(e)}")
    except FileNotFoundError:
        print_message("No history records found.")


def clear_history():
    history_file = HISTORY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    try:
        os.remove(history_file)
        print_message("黃泉 又一場雨，一場空白.")
    except FileNotFoundError:
        print_message("維里塔斯-拉帝奧 很苦惱的樣子啊,遇到麻煩了?既然如此--你自己想辦法吧.")


def check_for_updates():
    try:
        response = requests.get(UPDATE_URL)
        response.raise_for_status()
        latest_version = float(response.text.strip())
        return latest_version
    except requests.RequestException:
        return None


def handle_command(user_input):
    global username
    if user_input.lower() == "開拓":
        return False
    elif user_input.lower() == "帕姆":
        print_help()
    elif user_input.startswith("添加記憶"):
        new_key = user_input.split(" ", 1)[1]
        add_key(new_key)
    elif user_input.startswith("刪除記憶"):
        parts = user_input.split()
        if len(parts) == 2 and parts[0] == "刪除記憶" and parts[1].startswith("-"):
            key_number = parts[1][1:]
            delete_key(key_number)
        else:
            print_message(
                "帕姆 你忘了帕？格式是: 刪除記憶 -<key_number>"
            )
    elif user_input.lower() == "回到最初":
        reset()
    elif user_input.lower() == "查閱記憶":
        display_keys()
        print("")
    elif user_input.startswith("砂金"):
        text_to_crack = user_input.split(" ", 1)[1]
        bruteforce_decrypt(text_to_crack)
    elif user_input.lower() == "信差":
        display_history()
    elif user_input.lower() == "黃泉":
        clear_history()
    elif user_input.lower() == "嘗試躍遷":
        latest_version = check_for_updates()
        if latest_version:
            if latest_version > RCS_VER:
                print_message(
                    f"星際和平公司提醒您：{latest_version} "
                )
            else:
                print_message("星際和平公司提醒您：聯覺信標已是最新版本.")
        else:
            print_message("維里塔斯-拉帝奧 很苦惱的樣子啊,遇到麻煩了?既然如此--你自己想辦法吧.")
    elif user_input.startswith("- "):
        decrypt_text(user_input)
    else:
        encrypt_text(user_input)
    return True


def interactive_mode():
    global username
    
    print("---For entertainment only, it is recommended to use the official version---")
    print_message(
        f"聯覺信標{RCS_VER}, \nhttp://rcva.san.tc, Rin' Cynar\n瓦爾特-楊 無論何時需要幫助，「帕姆」都會及時趕到，不過請不要故意尋它開心，上一個這麼做的人已經......"
    )

    username = get_input("三月七 你好，歡迎入職星穹列車，我是三月七，星穹列車的成員，也是你的同事，現在，請先拍攝「入職照」.（用戶名）")
    key_file = KEY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )
    history_file = HISTORY_FILE_TEMPLATE.format(
        bytes_to_hex(rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")))
    )

    if not os.path.exists(RCS_FOLDER):
        os.mkdir(RCS_FOLDER)

    if not os.path.exists(key_file):
        encrypted_username = (
            rc4_encrypt(username.encode("utf-16"), username.encode("utf-16")) + b"\n"
        )
        with open(key_file, "wb") as file:
            file.write(encrypted_username)

    load_keys()
    if not os.path.exists(history_file):
        open(history_file, "wb").close()
        print(f"姬子 歡迎上車，{username} .")

    print(f"帕姆 {username}你回來啦！ ...\n帕姆 嗯，身上有些掛彩，在外面吃了不少苦頭吧？要準備醫療用品......\n帕姆 看你風塵僕僕的樣子，估計肚子也餓了，餐車上的食物也得補貨了.\n帕姆 走進來又是一地灰塵，晚點得打掃一遍.\n帕姆 好啦就這樣了，謝謝{username}乘客的配合！ \n")

    latest_version = check_for_updates()
    if latest_version:
        if latest_version > RCS_VER:
            print_message(
                f"星際和平公司提醒您：{latest_version} "
            )

    while True:
        try:
            user_input = input("# ").strip()
            if not handle_command(user_input):
                break
        except Exception as e:
            print_message(f"Error: {str(e)}")


def print_help():
    print_message(
        "帕姆 輸入文字並按下'Enter'確認，聯覺信標將把文字轉化為內在語言的編碼帕.您可以從「記憶」中選擇密鑰或簡單地再次按下'Enter'使用「博識學會」統一密碼帕.\n帕姆 輸入'-<編碼>'，聯覺信標將把密文處理還原.您可以透過'-<number>'從「記憶」中選取金鑰解密帕.\n銀狼 保持這個狀態，繼續按（Enter），不要停.\n帕姆 輸入'添加記憶<key>'覲見“浮黎（記憶星神）”，祂會幫你備份下密鑰.\n帕姆 輸入'黃泉'，這位虛無令使會進入「殘夢盡染，一刀繚斷」狀態，將您的查詢記錄拋向IX帕.\n帕姆 輸入'查閱記憶'覲見“浮黎（記憶星神），祂會向您展示您過去留存的密鑰帕.\n帕姆 輸入'刪除記憶-<number>'覲見“浮黎（記憶星神），祂會刪除制定的備份帕.\n帕姆 輸入'開拓'下車帕（退出終端）\n帕姆 輸入'信差'，她會幫您查閱查詢記錄帕.\n帕姆 輸入'砂金<text>' 向砂金求助不知道密鑰的密文，他的運氣一向很好帕.\n帕姆 輸入'回到最初' 回到黑塔空間站，卡芙卡會使用「言靈」使你回到初始狀態帕.\n帕姆 輸入'嘗試躍遷'檢查信標更新."
 )


def display_keys():
    global username
    print_message(f"{username} 當有機會做出選擇的時候，不要讓自己後悔")
    for i, key in enumerate(KEYS):
        print(f"{i}-{key}")


def decrypt_text(user_input):
    global KEYS, username
    parts = user_input.split(" ")
    if len(parts) < 2:
        print_message("維里塔斯-拉帝奧 很苦惱的樣子啊,遇到麻煩了?既然如此--你自己想辦法吧.")
        return

    text = parts[1]
    key_number = int(parts[2][1:]) if len(parts) > 2 else None

    if key_number is not None:
        if 0 <= key_number < len(KEYS):
            keys_to_try = [KEYS[key_number]]
        else:
            print_message(f"砂金 一枚不知價值的籌碼，一張不知花色的底牌... {key_number}")
            return
    else:
        keys_to_try = KEYS

    ciphertext_bytes = hex_to_bytes(text)
    decryption_results = []

    for key in keys_to_try:
        try:
            key_bytes = utf16_to_bytes(key)
            plaintext_bytes = rc4_decrypt(key_bytes, ciphertext_bytes)
            decrypted_text = plaintext_bytes.decode("utf-16")
            decryption_results.append(
                f"{username} 還難不倒我：{decrypted_text}.\n克拉拉 謝謝，克拉拉會記得妳的，{key[:3]}."
            )
        except Exception as e:
            decryption_results.append(f"卡芙卡 嗨，列車團...嗯，你們逮捕我啦.{key[:3]}")
            continue

    for result in decryption_results:
        print_message(result)
        save_history(result)


def encrypt_text(plaintext):
    global KEYS, username
    key = choose_key_for_encryption()
    key_bytes = utf16_to_bytes(key)
    plaintext_bytes = utf16_to_bytes(plaintext)
    ciphertext_bytes = rc4_encrypt(key_bytes, plaintext_bytes)
    ciphertext_hex = bytes_to_hex(ciphertext_bytes)
    print_message(f"克拉拉/史瓦羅 命令執行： {ciphertext_hex}")
    save_history(f"克拉拉/史瓦羅 命令執行： {ciphertext_hex} with key {key[:3]}")


def bruteforce_decrypt(ciphertext):
    global username
    character_set = "`~!@#$%^&*()-=_+[]\\{}|;':\",./<>?0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    print(f"砂金 不才「砂金」，隸屬星際和平公司戰略投資部，不良資產清算專家之一...當然，也可以是你的朋友.\n砂金 如何以一枚籌碼贏下整顆星球？規劃、經營、算計...但歸根究底，要歸於運氣。強運使人成為強者，攫取命運...沒錯，命運從一開始就不公平.")
    min_length = int(input("砂金 要不要來玩一把？最簡單的猜硬幣，看看今天運氣如何？最低長度是？"))
    max_length = int(input("砂金 嗯...最高長度呢？ "))

    with open(OPT_FILE, "w") as output_file:
        for length in range(min_length, max_length + 1):
            print(f"砂金 願母神三度為你閔眼...令你的血脈永遠鼓動，旅途永遠坦然，詭計永不敗露... {length}...")
            for attempt in itertools.product(character_set, repeat=length):
                key = "".join(attempt)
                try:
                    decrypted_text = rc4_decrypt(
                        utf16_to_bytes(key), hex_to_bytes(ciphertext)
                    )
                    decrypted_text = decrypted_text.decode("utf-16").rstrip("\x00")
                    output_file.write(f"Key: {key}, Decrypted text: {decrypted_text}\n")
                except Exception as e:
                    continue

    print("砂金 結果放在「opt.md」裡了，方才的交易愉快麼？目光放長遠些，這會是雙贏的選擇.\n")


if __name__ == "__main__":
    interactive_mode()
