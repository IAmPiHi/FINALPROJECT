import json
import os
import getpass
import re


# 全域變數
members = {}  # 會員列表，以帳號為鍵，密碼為值
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data.json")



# 初始化資料夾


# 資料管理模組
def save_data_to_file():
    """儲存所有資料到 JSON 檔案。"""
    with open(DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(members, file, indent=4)
    print("✅ 資料已儲存到 data.json 檔案。")

def load_data_from_file():
    """從 JSON 檔案載入資料。"""
    global members
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as file:
            members = json.load(file)
        print("✅ 資料已從 data.json 載入。")
    except FileNotFoundError:
        print("⚠️ 尚未有 data.json 檔案，將建立新檔案。")
    except json.JSONDecodeError:
        print("⚠️ 資料格式錯誤，無法載入資料。")





# 會員功能
def add_member():
    """新增會員，包含帳號與密碼。"""
    while True:
        member_id = input("請輸入會員ID（4到20個字元）： ").strip()
        # 檢查會員ID長度是否在 4 到 20 字元之間
        if len(member_id) < 3:
            print("❌ 會員ID長度必須至少 3 個字元！")
        elif len(member_id) > 20:
            print("❌ 會員ID長度不得超過 20 個字元！")
        elif member_id in members:
            print("❌ 此會員ID已存在！")
        else:
            break
    
    # 使用 getpass 來隱藏密碼輸入
    while True:
        password = getpass.getpass("請輸入會員密碼（至少6個字元，且包含英數字）： ").strip()
        # 檢查密碼長度和格式
        if len(password) < 6:
            print("❌ 密碼長度必須至少 6 個字元！")
        elif not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
            print("❌ 密碼必須包含至少一個字母和一個數字！")
        else:
            break
    
    members[member_id] = {"password": password}
    save_data_to_file()
    print(f"✅ 會員 {member_id} 已新增並儲存！")




def delete_member():
    """刪除會員。"""
    member_id = input("請輸入要刪除的會員ID： ").strip()
    if member_id in members:
        del members[member_id]
        save_data_to_file()
        print(f"✅ 會員 {member_id} 已刪除！")
    else:
        print("❌ 找不到該會員ID！")


def list_member():
    """列出所有會員的 ID 和密碼。"""
    if not members:
        print("📭 目前尚無會員記錄！")
    else:
        print("\n📋 已註冊會員列表：")
        print(f"{'ID':<20}")
        print("-" * 40)
        for member_id in members:
            print(f"{member_id:<20}")
        print("-" * 40)
        print(f"總共 {len(members)} 位會員。")


# 主功能選單
commands = {
    "1": ("新增會員", add_member),
    "2": ("刪除會員", delete_member),
    "3": ("會員列表", list_member),
    "0": ("離開系統", None),
}

# 主程式
if __name__ == "__main__":
    load_data_from_file()  # 系統啟動時載入資料

    while True:
        print("\n========== 會員管理系統 ==========")
        for cmd, (desc, _) in commands.items():
            print(f"{cmd}) {desc}")
        print("==============================")

        command = input("請輸入選項： ").strip()
        if command in commands:
            if command == "0":
                save_data_to_file()
                print("感謝使用！")
                break
            # 執行對應的功能
            _, action = commands[command]
            action()
        else:
            print("❌ 無效選項，請重新輸入。")