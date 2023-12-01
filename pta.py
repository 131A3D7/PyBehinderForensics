import base64
import os
import argparse
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii
import json

# 解析命令行参数
parser = argparse.ArgumentParser(description='冰蝎快速解析脚本')
parser.add_argument('-k', '--key', help='冰蝎解密的key, 默认是e45密钥',
                    required=False, default='e45e329feb5d925b')
parser.add_argument('-f', '--file', help='文件位置', required=True)
parser.add_argument('-d', '--decrypt', help='被加密的冰蝎shell文件', required=False)
parser.add_argument('-l', '--list', help='需要批量解密的目录', required=False)
args = parser.parse_args()

# 定义可能存在的key的正则表达式
maybe_aeskey = re.compile(r'[a-fA-F0-9]{16}')

# 打开文件并读取内容
with open(args.file, 'r', encoding='utf-8') as f:
    content = f.read()

# 定义寻找key的函数
def printmaybekey(check_key):
    if any(key != args.key for key in check_key):
        print('疑似检测到非默认密钥, 可能的key列表如下:')
        for i, key in enumerate(check_key, 1):
            print(f'{i}. {key}')
        print('请选择你想要运用来解密的key：')
        choose = int(input())
        if choose < 1 or choose > len(check_key):
            print('牛魔，参数乱填是吧')
        else:
            choose = choose - 1
            return check_key[choose]
    return args.key

# AES解密函数
def aes_decrypt(data, aes_key):
    try:
        iv = b'\x00' * 16
        cipher = AES.new(aes_key.encode('utf-8'), AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(base64.b64decode(data))
        return decrypted.rstrip(b"\0").decode('utf-8')
    except Exception as e:
        return '不是，你这key有问题啊'

# 检查是否为JSON
def is_json(decrypted_data):
    try:
        json.loads(decrypted_data)
        return True
    except ValueError:
        return False

# 找到所有符合16位hex的值
check_key = maybe_aeskey.findall(content)
aes_key = printmaybekey(check_key)

# 遍历目录，解密每个文件
def decrypt_directory(directory, aes_key):
    for filename in os.listdir(directory):
        if filename.endswith('.php'):  # 检查扩展名
            filepath = os.path.join(directory, filename)
            with open(filepath, 'rb') as f:
                encrypted_data = f.read().decode('utf-8')

            decrypted_data = aes_decrypt(encrypted_data, aes_key)
            new_filename = os.path.splitext(filepath)[0] + '_decrypted.txt'
            with open(new_filename, 'w') as f:
                f.write(decrypted_data)

# 根据参数处理单个文件或目录
if args.decrypt:
    with open(args.decrypt) as f:
        encrypt_file = f.read()

    decrypted_data = aes_decrypt(encrypt_file, aes_key)
    newfilename = 'decrypt_file.txt'
    with open(newfilename, 'w') as f:
        f.write(decrypted_data)

    match = re.search(r'\{.*\}', decrypted_data)
    if match:
        json_content = match.group(0)
        try:
            data = json.loads(json_content)
            decoded_status = base64.b64decode(data["status"]).decode('utf-8')
            decoded_msg = base64.b64decode(data["msg"]).decode('utf-8')
            print("Status:", decoded_status)
            print("Msg:", decoded_msg)
        except json.JSONDecodeError:
            print("提取的字符串不是有效的JSON格式。")
    else:
        print("未找到有效的JSON格式数据。是否直接输出(Y/N)")
        a = input()
        if a.lower() == 'y':
            print(decrypted_data)

elif args.list:
    decrypt_directory(args.list, aes_key)
