import base64
import os
import argparse
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii
import json
parser = argparse.ArgumentParser(description='冰蝎快速解析脚本')
parser.add_argument('-k', '--key', help='冰蝎解密的key, 默认是e45密钥',
                    required=False, default='e45e329feb5d925b')
parser.add_argument('-f', '--file', help='文件位置', required=True)
parser.add_argument('-d', '--decrypt', help='被加密的冰蝎shell', required=True)
args = parser.parse_args()

# 定义可能存在的key的正则表达式
maybe_aeskey = re.compile(r'[a-fA-F0-9]{16}')

# 打开文件并读取内容
with open(args.file, 'r', encoding='utf-8') as f:
    content = f.read()
    f.close

# 定义寻找key的函数


def printmaybekey(check_key):
    if any(key != args.key for key in check_key):
        print('疑似检测到非默认密钥, 可能的key列表如下:')
        for i, key in enumerate(check_key, 1):
            print(f'{i}. {key}')
        print('请选择你想要运用来解密的key：')
        choose = int(input())
        if (choose < 1 or choose > int(len(check_key))):
            print('牛魔，参数乱填是吧')
        else:
            choose = choose-1
            return check_key[choose]


def aes_decrypt(data, aes_key):
    try:
        iv = b'\x00'*16
        cipher = AES.new(aes_key.encode('utf-8'), AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(base64.b64decode(data))
        return decrypted.rstrip(b"\0").decode('utf-8')
    except Exception as e:
        return '不是，你这key有问题啊'


def is_json(decrypted_data):
    try:
        json.loads(decrypted_data)
    except ValueError:
        return False
    return True


# 找到所有符合16位hex的值
check_key = maybe_aeskey.findall(content)

aes_key = printmaybekey(check_key)


# 读取被加密的shell文件
with open(args.decrypt) as f:
    encrypt_file = f.read()
    f.close

decrypted_data = aes_decrypt(encrypt_file, aes_key)
print(decrypted_data)
newfilename = 'decrypt_file.txt'
with open(newfilename, 'w') as f:
    f.write(decrypted_data)

match = re.search(r'\{.*\}', decrypted_data)
if match:
    json_content = match.group(0)
    try:
        # 尝试解析JSON内容
        data = json.loads(json_content)

        # Base64解码
        decoded_status = base64.b64decode(data["status"]).decode('utf-8')
        decoded_msg = base64.b64decode(data["msg"]).decode('utf-8')

        print("Status:", decoded_status)
        print("Msg:", decoded_msg)
    except json.JSONDecodeError:
        print("提取的字符串不是有效的JSON格式。")
else:
    print("未找到有效的JSON格式数据。")
