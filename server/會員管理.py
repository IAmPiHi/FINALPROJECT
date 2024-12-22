import json
import os
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import base64
import hashlib
import logging
import sys
import threading
# 全域變數
members = []  # 會員列表
DATA_FILE = "data.json"
MEMBER_FILES_FOLDER = "member_files"
app = logging.getLogger('werkzeug')
app.setLevel(logging.ERROR)


# 初始化資料夾
os.makedirs(MEMBER_FILES_FOLDER, exist_ok=True)

# 初始化 Flask 應用程式
app = Flask(__name__)

# 資料管理模組
def save_data_to_file():
    """儲存所有資料到 JSON 檔案。"""
    data = {"members": members}
    with open(DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)
    print("✅ 資料已儲存到 data.json 檔案。")

def load_data_from_file():
    """從 JSON 檔案載入資料。"""
    global members
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            members = data.get("members", [])
        print("✅ 資料已從 data.json 載入。")
    except FileNotFoundError:
        print("⚠️ 尚未有 data.json 檔案，將建立新檔案。")
    except json.JSONDecodeError:
        print("⚠️ 資料格式錯誤，無法載入資料。")

# AES 加密與解密


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def pad_key(key):
    """填充密鑰至 16, 24 或 32 字元"""
    return key.ljust(32, 'X')[:32]

def pad_data(data):
    """對資料進行填充至16字元的倍數"""
    return data.ljust(16 * ((len(data) + 15) // 16), 'X')

def encrypt_aes(data, key):
    """使用 AES 加密資料"""
    key = pad_key(key).encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad_data(data)  # 填充資料
    encrypted = cipher.encrypt(padded_data.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt(enc, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(enc)).decode())
    return decrypted

# 固定密鑰 (伺服器開啟時生成)
server_key = os.urandom(16).hex()

# 會員功能
def add_member():
    """新增會員，包含帳號與密碼。"""
    member_id = input("請輸入會員ID： ").strip()
    if any(member["id"] == member_id for member in members):
        print("❌ 此會員ID已存在！")
        return
    password = input("請輸入會員密碼： ").strip()
    members.append({"id": member_id, "password": password})
    save_data_to_file()
    print(f"✅ 會員 {member_id} 已新增並儲存！")

def delete_member():
    """刪除會員。"""
    member_id = input("請輸入要刪除的會員ID： ").strip()
    for i, member in enumerate(members):
        if member["id"] == member_id:
            members.pop(i)
            save_data_to_file()
            print(f"✅ 會員 {member_id} 已刪除！")
            return
    print("❌ 找不到該會員ID！")

def manage_member_files():
    """管理會員檔案。列出某會員的資料夾內容。"""
    member_id = input("請輸入會員ID： ").strip()
    if not any(member["id"] == member_id for member in members):
        print("❌ 找不到該會員ID！")
        return
    member_folder = os.path.join(MEMBER_FILES_FOLDER, member_id)
    if not os.path.exists(member_folder):
        print("⚠️ 該會員沒有相關檔案資料夾！")
        return
    files = os.listdir(member_folder)
    if not files:
        print("📂 該會員的資料夾目前沒有任何檔案！")
    else:
        print("📂 該會員的檔案列表：")
        for file in files:
            print(f"- {file}")

# Flask 路由
@app.route('/ifserveron', methods=['GET'])
def server_status():
    """回傳伺服器狀態與加密密鑰。"""
    return jsonify({"status": "SERVER ON", "key": server_key})

@app.route('/login', methods=['GET'])
def login():
    """會員登入驗證，根據會員 ID 回傳密碼。"""
    account = request.args.get('acc')

    if not account:
        return jsonify({"error": "Invalid request data"}), 400

    for member in members:
        if member['id'] == account:  # 根據帳號找出會員
            return jsonify({"epwd": encrypt_aes(member['password'],member['password'])})

    return jsonify({"error": "Invalid credentials"}), 401

def list_member():
    """列出所有會員的 ID 和密碼。"""
    if not members:
        print("📭 目前尚無會員記錄！")
    else:
        print("\n📋 已註冊會員列表：")
        print(f"{'ID':<20} {'Password':<20}")
        print("-" * 40)
        for member in members:
            print(f"{member['id']:<20} {member['password']:<20}")
        print("-" * 40)
        print(f"總共 {len(members)} 位會員。")
# 主功能選單
commands = {
    "1": ("新增會員", add_member),
    "2": ("刪除會員", delete_member),
    "3": ("會員列表", list_member),
    "4": ("管理會員檔案", manage_member_files),
    "0": ("離開系統", None),
}

# 主程式
if __name__ == "__main__":
    load_data_from_file()  # 系統啟動時載入資料

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    # 隱藏 Flask 啟動訊息
    
   
    threading.Thread(target=lambda: app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)).start()

    

    while True:
        print("\n========== 會員管理系統 ==========")
        for cmd, (desc, _) in commands.items():
            print(f"{cmd}) {desc}")
        print("==============================")

        command = input("請輸入選項： ").strip()
        if command in commands:
            if command == "0":
                save_data_to_file()
                print("感謝使用，伺服器已關閉。")
                break
            # 執行對應的功能
            _, action = commands[command]
            
            action()
            
        else:
            print("❌ 無效選項，請重新輸入。")
