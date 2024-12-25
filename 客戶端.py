import tkinter as tk
from tkinter import messagebox, filedialog
import os
import requests
from Crypto.Cipher import AES 
import base64
import threading
import sys
import atexit
import shutil


server_ip = None  # 儲存伺服器 IP
serverkey = None  # 伺服器端金鑰
tokznglo = None 

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

def open_subwindow(previous_window, acc, tokzen):
    """主應用介面"""
    previous_window.destroy()

    subwindow = tk.Tk()
    subwindow.title("Yuntech Media App")
    subwindow.geometry("800x600")
    subwindow.resizable(False, False)
    fileDir = os.path.dirname(__file__)
    
    logoPath = os.path.join(fileDir, 'AnyConv.com__title.ico')  # 圖示檔完整路徑

# 確保檔案路徑存在
    if not os.path.exists(logoPath):
      messagebox.showerror("Error", f"Logo file not found: {logoPath}")
    else:
      subwindow.iconbitmap(logoPath)
      atexit.register(on_closing)

    # 主背景
    subwindow.config(bg="#f1f1f1")

    # 左側按鈕區
    button_frame = tk.Frame(subwindow, bg="#2E3B4E", width=200, padx=5, pady=5)
    button_frame.grid(row=0, column=0, sticky="ns")

    # 右側內容顯示區
    content_frame = tk.Frame(subwindow, bg="white", name="content_frame", padx=10, pady=10)
    content_frame.grid(row=0, column=1, sticky="nsew")

    # 定義按鈕及其對應內容
    buttons = [
        (f"會員: {acc}", None),  # 移除會員按鈕功能
        ("影音區", "MusicAndVideo"),
        ("PDF區", "PDF File"),
        ("圖片區", "JPG File"),
    ]

    for i, (button_text, content_type) in enumerate(buttons):
        tk.Button(
            button_frame,
            text=button_text,
            bg="#4C5C6A" if i  != 0 else "#3E4A59",  # 更深的顏色
            fg="yellow" if i  != 0 else "black",  # 按鈕字體顏色
            font=("Arial", 12, "bold"),
            height=2,
            command=(lambda c_type=content_type: update_content(content_frame, c_type, tokzen)) if content_type else None,
            relief="flat",
            bd=0,
            padx=5,
            pady=10
        ).pack(fill="x", pady=5)

    # 登出按鈕
    tk.Button(
        button_frame,
        text="登出",
        command=subwindow.destroy,
        bg="#FF4D4D",  # 紅色登出
        fg="white",
        font=("Arial", 12, "bold"),
        relief="flat",
        bd=0,
        padx=5,
        pady=10
    ).pack(side="bottom", fill="x", pady=10)

    # 設置自適應
    subwindow.grid_rowconfigure(0, weight=1)
    subwindow.grid_columnconfigure(1, weight=1)

def update_content(frame, content_type, acc):
    """更新右側顯示內容"""
    for widget in frame.winfo_children():
        widget.destroy()

    folder_mapping = {
        "MusicAndVideo": "Video",
        "PDF File": "PDF",
        "JPG File": "image"
    }
    folders_mapping = {
        "MusicAndVideo": "影音",
        "PDF File": "PDF",
        "JPG File": "圖片"
    }

    folder_name = folder_mapping.get(content_type, "未知類型")
    namet = folders_mapping.get(content_type, "未知類型")

    # 標題區域
    tk.Label(
        frame, text=f"{namet}區", font=("Arial", 16, "bold"), bg="#f8f9fa", fg="#333333"
    ).pack(pady=10)

    # 檔案列表區域框架
    list_frame = tk.Frame(frame, bg="#ffffff", relief="groove", bd=1)
    list_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # 創建滾動條框架
    scroll_canvas = tk.Canvas(list_frame, bg="#ffffff", highlightthickness=0)
    scroll_canvas.pack(side="left", fill="both", expand=True)

    scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=scroll_canvas.yview)
    scrollbar.pack(side="right", fill="y")

    scroll_canvas.configure(yscrollcommand=scrollbar.set)

    inner_frame = tk.Frame(scroll_canvas, bg="#ffffff")
    scroll_canvas.create_window((0, 0), window=inner_frame, anchor="nw")

    def on_configure(event):
        scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all"))

    inner_frame.bind("<Configure>", on_configure)

    files = fetch_files_from_server(acc, folder_name)

    if files:
        for file in files:
            file_frame = tk.Frame(inner_frame, bg="#ffffff", relief="groove", bd=1)
            file_frame.pack(pady=5, padx=5, fill="x")

            tk.Button(
                file_frame,
                text=file,
                bg="#ffffff",
                fg="#000000",
                font=("Arial", 12),
                anchor="w",
                justify="left",
                command=lambda f=file: download_and_open_file(f, folder_name, acc)
            ).pack(side="left", fill="x", expand=True, padx=10, pady=5)

            tk.Button(
                file_frame,
                text="刪除",
                bg="#f44336",
                fg="white",
                font=("Arial", 12),
                command=lambda f=file: delete_file_from_server(f, folder_name, acc, frame, content_type),
                relief="flat",
                padx=10
            ).pack(side="right", padx=10, pady=5)
    else:
        tk.Label(inner_frame, text="沒有檔案", bg="#ffffff", fg="#888888", font=("Arial", 12)).pack(pady=20)

    # 上傳按鈕區域
    button_frame = tk.Frame(frame, bg="#f8f9fa")
    button_frame.pack(fill="x", pady=10)

    upload_button = tk.Button(
        button_frame,
        text="上傳檔案",
        command=lambda: upload_file_to_server(folder_name, acc, frame, content_type),
        bg="#2196F3",
        fg="white",
        font=("Arial", 14, "bold"),
        relief="flat",
        padx=20,
        pady=10
    )
    upload_button.pack(pady=10)

# 為frame配置背景色
    frame.configure(bg="#f8f9fa")
 


def fetch_files_from_server(account, folder_name):
    """從伺服器獲取檔案列表"""
    try:
        url = f"http://{server_ip}/list_files?tokzen={account}&folder={folder_name}"
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
        url = f"http://{server_ip}/download?tokzen={account}&folder={folder_name}&file={file_name}"
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            local_folder = os.path.join("temp", folder_name)
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




def on_closing():
    url = f"http://{server_ip}/logout?tokzen={tokznglo}"
    response = requests.get(url, stream=True)
    """關閉應用程式時刪除 temp 資料夾"""
    temp_folder = "temp"
    if os.path.exists(temp_folder):
        try:
            shutil.rmtree(temp_folder)
        except Exception as e:
            messagebox.showerror("錯誤", f"無法刪除 temp 資料夾: {e}")
    





def upload_file_to_server(folder_name, account, frame, content_type):
    """上傳檔案至伺服器"""
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    # 定義允許的檔案類型
    allowed_extensions = {
        "PDF File": [".pdf"],
        "MusicAndVideo": [".mp3", ".mp4", ".wav"],
        "JPG File": [".png", ".jpg", ".jpeg", ".gif"]
    }

    # 根據 content_type 獲取允許的副檔名
    valid_extensions = allowed_extensions.get(content_type, [])
    file_extension = os.path.splitext(file_path)[1].lower()

    if file_extension not in valid_extensions:
        messagebox.showerror("錯誤", f"不支援的檔案類型！僅支援以下類型: {', '.join(valid_extensions)}")
        return

    try:
        file_name = os.path.basename(file_path)
        url = f"http://{server_ip}/upload"
        files = {
            "file": (file_name, open(file_path, "rb"))
        }
        data = {
            "tokzen": account,
            "folder": folder_name,
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

def decrypt_aes(data, key):
    key = pad_key(key).encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(data.encode('utf-8')))
    return decrypted.decode('utf-8').rstrip('X')


def delete_file_from_server(file_name, folder_name, account, frame, content_type):
    """刪除伺服器上的檔案"""
    try:
        url = f"http://{server_ip}/delete"
        data = {
            "tokzen": account,
            "folder": folder_name,
            "file": file_name
        }
        response = requests.post(url, json=data)
        if response.status_code == 200:
            messagebox.showinfo("成功", "檔案刪除成功！")
            update_content(frame=frame, content_type=content_type, acc=account)
        else:
            raise ValueError("伺服器回應刪除失敗")
    except Exception as e:
        messagebox.showerror("錯誤", f"檔案刪除失敗: {e}")


class App:
    @staticmethod
    def login_interface():
        root.destroy()
        login = tk.Tk()
        login.title("Yuntech Media App")
        login.resizable(False, False)
        logoPath = os.path.join(fileDir, 'AnyConv.com__title.ico')  # 圖示檔完整路徑

# 確保檔案路徑存在
        if not os.path.exists(logoPath):
          messagebox.showerror("Error", f"Logo file not found: {logoPath}")
        else:
          login.iconbitmap(logoPath)
        login.configure(bg="#f0f0f0")

        # 標題
        tk.Label(
            login,
            text="會員登入",
            font=("Arial", 16, "bold"),
            bg="#f0f0f0",
            fg="#333333"
        ).grid(row=0, column=0, columnspan=2, pady=(10, 20))

        # 帳號輸入框
        tk.Label(
            login,
            text="帳號",
            font=("Arial", 12),
            bg="#f0f0f0",
            fg="#333333"
        ).grid(row=1, column=0, padx=10, pady=5, sticky="e")

        entry1 = tk.Entry(
            login,
            font=("Arial", 12),
            width=25,
            bd=2,
            relief="groove"
        )
        entry1.grid(row=1, column=1, padx=10, pady=5)

        # 密碼輸入框
        tk.Label(
            login,
            text="密碼",
            font=("Arial", 12),
            bg="#f0f0f0",
            fg="#333333"
        ).grid(row=2, column=0, padx=10, pady=5, sticky="e")

        entry2 = tk.Entry(
            login,
            show="*",
            font=("Arial", 12),
            width=25,
            bd=2,
            relief="groove"
        )
        entry2.grid(row=2, column=1, padx=10, pady=5)

        # 登入按鈕
        tk.Button(
            login,
            text="登入",
            command=lambda: App.send_login(entry1.get(), entry2.get(), login),
            font=("Arial", 12, "bold"),
            bg="#4CAF50",
            fg="white",
            relief="flat",
            padx=10,
            pady=5
        ).grid(row=3, column=0, columnspan=2, pady=20)

        # 設置固定寬度
        login.grid_columnconfigure(0, weight=1)
        login.grid_columnconfigure(1, weight=1)
    @staticmethod
    @staticmethod
    def send_login(account, password, login_window):
     if not account or not password:
        messagebox.showerror("Error", "請輸入帳號和密碼！")
        return

     try:
        # 加密密碼，使用密碼本身經過 pad_key 作為密鑰
        encrypted_password = encrypt_aes(password, pad_key(password))
        global tokznglo
        # 設置登入的 URL
        url = f"http://{server_ip}/login"

        # 發送 POST 請求
        data = {
            "account": account,
            "encrypted_password": encrypted_password
        }
        response = requests.post(url, json=data)

        # 處理伺服器回應
        if response.status_code == 200 and response.json().get("status") == "success":
            tokzen = response.json().get("tokzen")
            tokzen = decrypt_aes(tokzen,password)
            tokznglo = tokzen
            open_subwindow(login_window, account,tokzen)
        else:
            messagebox.showerror("Error", "登入失敗，請檢查帳號或密碼！")

     except Exception as e:
        messagebox.showerror("Error", f"伺服器連線失敗：{e}")


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
root.geometry("400x200")  # 設置視窗大小
root.resizable(False, False)  # 禁止隨意改變大小

# 使輸入框和按鈕置中
root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=1)
root.grid_rowconfigure(2, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

tk.Label(root, text="請輸入伺服器 IP", font=("Arial", 14, "bold"), bg="#f8f9fa", fg="#333333").grid(
    row=0, column=0, columnspan=2, pady=20
)

server_ip_entry = tk.Entry(root, width=30, font=("Arial", 12), relief="groove", bd=2)
server_ip_entry.grid(row=1, column=0, columnspan=2, pady=10)

tk.Button(
    root,
    text="連線",
    command=lambda: App.check_server(server_ip_entry.get()),
    bg="#4CAF50",
    fg="white",
    font=("Arial", 12, "bold"),
    relief="flat",
    padx=10,
    pady=5
).grid(row=2, column=0, columnspan=2, pady=20)

root.configure(bg="#f8f9fa")
fileDir = os.path.dirname(__file__)

logoPath = os.path.join(fileDir, 'AnyConv.com__title.ico')  # 圖示檔完整路徑

# 確保檔案路徑存在
if not os.path.exists(logoPath):
    messagebox.showerror("Error", f"Logo file not found: {logoPath}")
else:
    root.iconbitmap(logoPath)
root.mainloop()
stop_checking = True