from flask import Flask, request, jsonify, send_file
import logging
import os
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
import base64
import json
import string
from datetime import datetime
import random

app = Flask(__name__)
tokzenmap = {}
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
# 設定伺服器目錄結構
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# AES 加密相關函數
def pad_key(key):
    return key.ljust(32, 'X')[:32]

def pad_data(data):
    return data.ljust(16 * ((len(data) + 15) // 16), 'X')

def encrypt_aes(data, key):
    key = pad_key(key).encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad_data(data)
    encrypted = cipher.encrypt(padded_data.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_aes(data, key):
    key = pad_key(key).encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(data.encode('utf-8')))
    return decrypted.decode('utf-8').rstrip('X')

@app.route('/ifserveron', methods=['GET'])
def check_server():
    return jsonify({"status": "SERVER ON"}), 200

def generate_unique_token(length=16):
    while True:
        tokzen = generate_token(length)
        if tokzen not in tokzenmap:
            return tokzen


def generate_token(length=16):
    """產生隨機長度為 16 的 token"""
    characters = string.ascii_letters + string.digits  # 包含大小寫字母和數字
    token = ''.join(random.choices(characters, k=length))
    return token

@app.route('/login', methods=['POST'])
def login():
    # 從請求中獲取 JSON 資料
    data = request.json
    account = data.get("account")
    encrypted_password = data.get("encrypted_password")

    if not account or not encrypted_password:
        return jsonify({"error": "Missing account or password"}), 400

    # 讀取本地 data.json 文件
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATA_FILE = os.path.join(BASE_DIR, "data.json")
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as file:
            users = json.load(file)
    except FileNotFoundError:
        return jsonify({"error": "User database not found"}), 500
    except json.JSONDecodeError:
        return jsonify({"error": "User database is corrupted"}), 500

    # 驗證帳號是否存在
    user_data = users.get(account)
    if not user_data:
        return jsonify({"error": "Invalid account"}), 404

    # 使用密碼本身經過 pad_key 進行解密驗證
    try:
        decrypted_password = decrypt_aes(encrypted_password, user_data["password"])
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {e}"}), 400

    if decrypted_password == user_data["password"]:
        tokzentemp = generate_unique_token()
        tokzenmap[tokzentemp] = account
        now = datetime.now()
        current_time = now.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{current_time}]使用者:{account} 登入系統!" )
        return jsonify({"status": "success", "tokzen": f"{tokzentemp}"}), 200
        
    else:
        return jsonify({"error": "Invalid password"}), 403

@app.route('/list_files', methods=['GET'])
def list_files():
    tokzen = request.args.get('tokzen')
    folder = request.args.get('folder')
    user_account = tokzenmap.get(tokzen)
    if not user_account or not folder:
        return jsonify({"error": "Missing parameters"}), 400

    account_folder = os.path.join(UPLOAD_FOLDER, secure_filename(tokzenmap[tokzen]), secure_filename(folder))
    os.makedirs(account_folder, exist_ok=True)
    files = os.listdir(account_folder)
    return jsonify({"files": files}), 200

@app.route('/download', methods=['GET'])
def download_file():
    tokzen = request.args.get('tokzen')
    folder = request.args.get('folder')
    file_name = request.args.get('file')
    user_account = tokzenmap.get(tokzen)
    if not user_account or not folder or not file_name:
        return jsonify({"error": "Missing parameters"}), 400

    file_path = os.path.join(UPLOAD_FOLDER, secure_filename(tokzenmap[tokzen]), secure_filename(folder), secure_filename(file_name))
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    return send_file(file_path, as_attachment=True)

@app.route('/upload', methods=['POST'])
def upload_file():
    tokzen = request.form.get('tokzen')
    folder = request.form.get('folder')
    file = request.files.get('file')
    
    user_account = tokzenmap.get(tokzen)


    if not user_account or not folder or not file:
        return jsonify({"error": "Missing parameters"}), 400

    account_folder = os.path.join(UPLOAD_FOLDER, secure_filename(tokzenmap[tokzen]), secure_filename(folder))
    os.makedirs(account_folder, exist_ok=True)

    file_path = os.path.join(account_folder,secure_filename(file.filename))
    file.save(file_path)
    now = datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{current_time}]使用者:{tokzenmap[tokzen]} 上傳了 {file.filename} 到伺服器端! 位於:{file_path}" )
    return jsonify({"message": "File uploaded successfully"}), 200

BASE_DIRECTORY = "./server_files"  # 伺服器上存儲檔案的根目錄

@app.route('/delete', methods=['POST'])
def delete_file():
    """處理檔案刪除請求"""
    try:
        data = request.json
        tokzen = data.get("tokzen")
        folder_name = data.get("folder")
        file_name = data.get("file")
        user_account = tokzenmap.get(tokzen)
        if not all([user_account, folder_name, file_name]):
            return jsonify({"status": "error", "message": "缺少必要參數"}), 400

        # 檔案的完整路徑基於 UPLOAD_FOLDER
        file_path = os.path.join(UPLOAD_FOLDER, secure_filename(tokzenmap[tokzen]), secure_filename(folder_name), secure_filename(file_name))

        if os.path.exists(file_path):
            now = datetime.now()
            current_time = now.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{current_time}]使用者:{tokzenmap[tokzen]} 刪除位於:{file_path} 的檔案:{file_name}" )
            os.remove(file_path)
            return jsonify({"status": "success", "message": "檔案已刪除"}), 200
        else:
            return jsonify({"status": "error", "message": "檔案不存在"}), 404

    except Exception as e:
        return jsonify({"status": "error", "message": f"伺服器錯誤: {e}"}), 500

@app.route('/logout', methods=['GET'])
def logout():
    tokzen = request.args.get('tokzen')
    
    if not tokzen:
        return jsonify({"error": "Missing tokzen"}), 400
    temp = tokzenmap.pop(tokzen, None)
    # 嘗試從 tokzenmap 移除 tokzen
    if temp is not None:
        now = datetime.now()

# 格式化輸出年、月、日、時、分、秒
        current_time = now.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{current_time}]使用者:{temp} 已登出!" )
        return "logouted"
    else:
        return jsonify({"error": "Invalid or expired tokzen"}), 400


if __name__ == '__main__':
    import socket

# 獲取本機的 IPv4 地址
    host_name = socket.gethostname()  # 獲取本機名稱
    ip_address = socket.gethostbyname(host_name)  # 通過主機名獲取對應的 IP 地址

    print("伺服器已於IPv4:", ip_address,":5000 位置上運行")
    app.run(host='0.0.0.0', port=5000, debug=True)

