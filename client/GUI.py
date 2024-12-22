import tkinter as tk
from tkinter import messagebox, filedialog
import os
import requests
from Crypto.Cipher import AES
import base64
import threading
import sys

server_ip = None  # 儲存伺服器 IP
serverkey = None  # 伺服器端金鑰

# 主視窗設定
root = tk.Tk()
root.title('Yuntech多媒體APP')
root.geometry("400x200")

stop_checking = False  # 用來結束執行程序的標誌

def check_server_status():
    """每秒檢查伺服器是否在線"""
    global server_ip
    if not server_ip:
        return

    url = f"http://{server_ip}/ifserveron"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200 and response.json().get("status") == "SERVER ON":
            # 伺服器正常，繼續檢查
            root.after(1000, check_server_status)
        else:
            raise ValueError("伺服器回應不正確")
    except Exception as e:
        messagebox.showerror("Error", "伺服器已關閉！")
        sys.exit()

def start_server_check_thread():
    """啟動能多程序的檢查程序"""
    thread = threading.Thread(target=check_server_status, daemon=True)
    thread.start()

def open_subwindow(previous_window, acc):
    """主應用介面"""
    previous_window.destroy()

    subwindow = tk.Tk()
    subwindow.title("Yuntech Music App")
    subwindow.geometry("800x600")
    subwindow.resizable(False, False)

    # 左側按鈕區
    button_frame = tk.Frame(subwindow, bg="lightgray", width=200)
    button_frame.grid(row=0, column=0, sticky="ns")

    # 右側內容顯示區
    content_frame = tk.Frame(subwindow, bg="white", name="content_frame")
    content_frame.grid(row=0, column=1, sticky="nsew")

    # 定義按鈕及其對應內容
    buttons = [
        (f"會員:{acc}", None),  # 移除會員按鈕功能
        ("影音區", "MusicAndVideo"),
        ("PDF區", "PDF File"),
        ("圖片區", "JPG File"),
    ]

    for i, (button_text, content_type) in enumerate(buttons):
        tk.Button(
            button_frame,
            text=button_text,
            bg="gray" if i % 2 == 0 else "black",
            fg="white" if i % 2 == 1 else "black",
            height=4,
            command=(lambda c_type=content_type: update_content(content_frame, c_type, acc)) if content_type else None,
        ).pack(fill="x")

    # 增加一個登出按鈕
    tk.Button(button_frame, text="登出", command=subwindow.destroy).pack(side="bottom", fill="x")

    # 設置自適應
    subwindow.grid_rowconfigure(0, weight=1)
    subwindow.grid_columnconfigure(1, weight=1)

def update_content(frame, content_type, acc):
    """更新右側顯示內容"""
    for widget in frame.winfo_children():
        widget.destroy()

    folder_mapping = {
        "MusicAndVideo": "影音",
        "PDF File": "PDF",
        "JPG File": "圖片"
    }

    folder_name = folder_mapping.get(content_type, "未知類型")

    tk.Label(frame, text=f"{folder_name}區", font=("Arial", 16), bg="white").pack(pady=10)

    files = fetch_files_from_server(acc, folder_name)

    if files:
        for file in files:
            tk.Button(
                frame,
                text=file,
                command=lambda f=file: download_and_open_file(f, folder_name, acc)
            ).pack(pady=5)
    else:
        tk.Label(frame, text="沒有檔案", bg="white").pack(pady=10)

    # 上傳按鈕
    tk.Button(
        frame,
        text="上傳檔案",
        command=lambda: upload_file_to_server(folder_name, acc, frame, content_type)
    ).pack(pady=20)

def fetch_files_from_server(account, folder_name):
    """從伺服器獲取檔案列表"""
    try:
        url = f"http://{server_ip}/list_files?account={account}&folder={folder_name}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json().get("files", [])
        else:
            raise ValueError("無法獲取檔案列表")
    except Exception as e:
        messagebox.showerror("錯誤", f"無法連接伺服器: {e}")
        return []

def download_and_open_file(file_name, folder_name, account):
    """下載並打開檔案"""
    try:
        url = f"http://{server_ip}/download?account={account}&folder={folder_name}&file={file_name}"
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            local_folder = os.path.join("downloads", account, folder_name)
            os.makedirs(local_folder, exist_ok=True)
            local_file_path = os.path.join(local_folder, file_name)
            with open(local_file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            os.startfile(local_file_path)
        else:
            raise ValueError("無法下載檔案")
    except Exception as e:
        messagebox.showerror("錯誤", f"檔案下載失敗: {e}")

def upload_file_to_server(folder_name, account, frame, content_type):
    """上傳檔案至伺服器"""
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    try:
        file_name = os.path.basename(file_path)
        url = f"http://{server_ip}/upload"
        files = {
            "file": (file_name, open(file_path, "rb"))
        }
        data = {
            "account": account,
            "folder": folder_name
        }
        response = requests.post(url, files=files, data=data)
        if response.status_code == 200:
            messagebox.showinfo("成功", "檔案上傳成功！")
            update_content(frame=frame, content_type=content_type, acc=account)
        else:
            raise ValueError("伺服器回應失敗")
    except Exception as e:
        messagebox.showerror("錯誤", f"檔案上傳失敗: {e}")

def pad_key(key):
    """填充密鑰至16, 24 或 32 字元"""
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

class App:
    @staticmethod
    def login_interface():
        root.destroy()
        login = tk.Tk()
        login.title("Yuntech Music App")
        login.resizable(False, False)

        tk.Label(login, text="帳號", font=10).grid(row=0, column=0, padx=5, pady=5)
        tk.Label(login, text="密碼", font=10).grid(row=1, column=0, padx=5, pady=5)

        entry1 = tk.Entry(login)
        entry2 = tk.Entry(login, show="*")
        entry1.grid(row=0, column=1, padx=5, pady=5)
        entry2.grid(row=1, column=1, padx=5, pady=5)

        tk.Button(login, text="登入", command=lambda: App.send_login(entry1.get(), entry2.get(), login), font=8).grid(row=2, column=0, columnspan=2, pady=10)

    @staticmethod
    def send_login(account, password, login_window):
        if not account or not password:
            messagebox.showerror("Error", "請輸入帳號和密碼！")
            return

        # 加密帳號和密碼
        encrypted_password = encrypt_aes(password, password)

        # 使用用戶輸入的伺服器 IP
        url = f"http://{server_ip}/login?acc={account}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200 and response.json().get("epwd") == encrypted_password:
                open_subwindow(login_window, account)
            else:
                messagebox.showerror("Error", "伺服器回應不正確或尚未開啟！")

        except requests.RequestException:
            messagebox.showerror("Error", "無法連線到伺服器，請確認 IP 是否正確且伺服器已開啟！")

    @staticmethod
    def check_server(ip):
        """檢查伺服器是否可用"""
        global server_ip
        server_ip = ip.strip()  # 儲存伺服器 IP

        url = f"http://{server_ip}/ifserveron"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200 and response.json().get("status") == "SERVER ON":
                start_server_check_thread()
                App.login_interface()
            else:
                messagebox.showerror("Error", "伺服器回應不正確或尚未開啟！")
        except requests.RequestException:
            messagebox.showerror("Error", "無法連線到伺服器，請確認 IP 是否正確且伺服器已開啟！")

# 輸入伺服器 IP 的介面
tk.Label(root, text="請輸入伺服器 IP").grid(row=0, column=0, columnspan=2, pady=10)
server_ip_entry = tk.Entry(root, width=30)
server_ip_entry.grid(row=1, column=0, columnspan=2, pady=5)

tk.Button(root, text="連線", command=lambda: App.check_server(server_ip_entry.get())).grid(row=2, column=0, columnspan=2, pady=10)

root.mainloop()
stop_checking = True
