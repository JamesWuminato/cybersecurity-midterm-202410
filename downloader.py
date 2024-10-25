import requests
import os, sys
import argparse
import time
import json
from pathlib import Path

def get_task_status(url, task_id, headers):
    """檢查任務狀態"""
    status_url = f"{url.rstrip('/')}/tasks/view/{task_id}"
    try:
        r = requests.get(status_url, headers=headers)
        r.raise_for_status()
        return r.json()["task"]["status"]
    except Exception as e:
        print(f"檢查任務 {task_id} 狀態時發生錯誤: {str(e)}")
        return "error"

def download_analysis_files(url, task_id, filename, output_folder, headers):
    """整合下載分析報告和PCAP檔案"""
    # 準備檔案路徑，使用原始檔名作為基礎
    report_file = os.path.join(output_folder, f"{filename}_analysis.json")
    pcap_file = os.path.join(output_folder, f"{filename}.pcap")
    
    success = True
    
    # 下載分析報告
    report_url = f"{url.rstrip('/')}/tasks/report/{task_id}"
    try:
        r = requests.get(report_url, headers=headers)
        r.raise_for_status()
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(r.json(), f, indent=2)
        print(f"已下載分析報告: {report_file}")
    except Exception as e:
        print(f"下載分析報告失敗 ({filename}): {str(e)}")
        success = False

    # 下載PCAP檔案
    pcap_url = f"{url.rstrip('/')}/pcap/{task_id}"
    try:
        r = requests.get(pcap_url, headers=headers)
        r.raise_for_status()
        with open(pcap_file, 'wb') as f:
            f.write(r.content)
        print(f"已下載PCAP檔案: {pcap_file}")
    except Exception as e:
        print(f"下載PCAP檔案失敗 ({filename}): {str(e)}")
        success = False
        
    return success

def main():
    # [前面的程式碼保持不變...]
    # get current directory
    current_dir = os.getcwd()
    
    REST_url = "http://localhost:8090/tasks/create/file"
    header = {"Authorization": "Bearer Udc5HKZB1aruy8e-Glv_fg"}  # 請在此處加入你的 API token
    file = os.path.join(current_dir, '/upload')
    output = os.path.join(current_dir, '/cuckoo reports')

    parser = argparse.ArgumentParser(description="上傳檔案至 Cuckoo sandbox 並下載分析報告")
    parser.add_argument('--url', type=str, help='Cuckoo sandbox 的位置', default=REST_url)
    parser.add_argument('--file', type=str, help='要上傳的檔案目錄', default=file)
    parser.add_argument('--output', type=str, help='報告下載位置', default=output)
    args = parser.parse_args()
    
    #確保輸入目錄存在
    if not os.path.exists(args.file):
        print(f"錯誤：上傳目錄 '{args.file}' 不存在。請確認目錄路徑是否正確，或使用 --file 參數指定正確的目錄。")
        sys.exit(1)


    # 確保輸出目錄存在
    if not os.path.exists(args.output):
        os.makedirs(args.output)

    # 處理每個資料夾
    allFiles = os.listdir(args.file)
    for folder in allFiles:
        folder_path = os.path.join(args.file, folder)
        if not os.path.isdir(folder_path):
            continue
            
        # 建立對應的輸出資料夾
        output_folder = os.path.join(args.output, folder)
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
            
        # 儲存task_id的檔案
        task_file = os.path.join(output_folder, "task_ids.txt")
        task_ids = []
        
        # 上傳檔案
        print(f"\n處理資料夾: {folder}")
        filenames = os.listdir(folder_path)
        for filename in filenames:
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path):
                # 檢查是否已經有分析報告
                if os.path.exists(os.path.join(output_folder, f"{filename}_analysis.json")):
                    print(f"跳過已分析的檔案: {filename}")
                    continue
                    
                try:
                    with open(file_path, "rb") as file_in_folder:
                        files = {"file": (filename, file_in_folder)}
                        r = requests.post(args.url, headers=header, files=files)
                        r.raise_for_status()
                        task_id = r.json()["task_id"]
                        task_ids.append((task_id, filename))
                        print(f"已上傳 {filename}, task_id: {task_id}")
                except Exception as e:
                    print(f"上傳 {filename} 時發生錯誤: {str(e)}")
        
        # 儲存task_ids
        with open(task_file, "w") as f:
            for task_id, filename in task_ids:
                f.write(f"{task_id},{filename}\n")
        
        # 等待分析完成並下載報告
        print("\n等待分析完成並下載結果...")
        for task_id, filename in task_ids:
            # 等待分析完成
            while True:
                status = get_task_status(args.url, task_id, header)
                if status == "reported":
                    break
                elif status in ["failed", "error"]:
                    print(f"任務 {task_id} ({filename}) 失敗")
                    break
                print(f"等待任務 {task_id} ({filename}) 完成...目前狀態: {status}")
                time.sleep(30)
            
            # 下載分析結果
            if status == "reported":
                download_success = download_analysis_files(
                    args.url,
                    task_id,
                    filename,
                    output_folder,
                    header
                )
                if not download_success:
                    print(f"部分或全部檔案下載失敗: task_id {task_id} ({filename})")

if __name__ == "__main__":
    main()
