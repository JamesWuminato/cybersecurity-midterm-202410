import requests
import os, sys
import argparse
import time
import json
from pathlib import Path

def get_task_status(url, task_id, headers):
    """CHECK CURRENT TASK STATUS"""
    base_url = url.split('/tasks/')[0]
    status_url = f"{base_url}/tasks/view/{task_id}"
    try:
        r = requests.get(status_url, headers=headers)
        r.raise_for_status()
        return r.json()["task"]["status"]
    except Exception as e:
        print(f"ERROR OCCUR AT TASK{task_id}:{str(e)}")
        return "error"

def download_analysis_files(url, task_id, filename, output_folder, headers):
    """DOWNLOAD JSON AND PCAP"""
    base_url = url.split('/tasks/')[0]

    report_file = os.path.join(output_folder, f"{filename}_analysis.json")
    pcap_file = os.path.join(output_folder, f"{filename}.pcap")
    
    success = True
    
    report_url = f"{base_url}/tasks/report/{task_id}"
    try:
        r = requests.get(report_url, headers=headers)
        r.raise_for_status()
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(r.json(), f, indent=2)
        print(f"File downloaded: {report_file}")
    except Exception as e:
        print(f"download file failed ({filename}): {str(e)}")
        success = False

    pcap_url = f"{base_url}/pcap/get/{task_id}"
    try:
        r = requests.get(pcap_url, headers=headers)
        r.raise_for_status()
        with open(pcap_file, 'wb') as f:
            f.write(r.content)
        print(f"pcap downloaded : {pcap_file}")
    except Exception as e:
        print(f"download pcap failed ({filename}): {str(e)}")
        success = False
        
    return success

def main():
    # get current directory
    current_dir = os.getcwd()
    
    REST_url = "http://localhost:8090/tasks/create/file"
    header = {"Authorization": "Bearer UdC5HKZB1aruy8e-Giv_fg"}  # USE YOUR API token HERE
    file = os.path.join(current_dir, 'upload')
    output = os.path.join(current_dir, 'cuckoo_reports')

    parser = argparse.ArgumentParser(description="UPLOAD TO Cuckoo sandbox AND DOWNLOAD REPORT")
    parser.add_argument('--url', type=str, help='Cuckoo sandbox location', default=REST_url)
    parser.add_argument('--file', type=str, help='upload directory', default=file)
    parser.add_argument('--output', type=str, help='download directory', default=output)
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"error：directory '{args.file}' not exist")
        sys.exit(1)

    if not os.path.exists(args.output):
        os.mkdir(args.output)

    task_file = os.path.join(args.output, "task_ids.txt")
    task_ids = []

    allFiles = os.listdir(args.file)
    for folder in allFiles:
        folder_path = os.path.join(args.file, folder)
        print(f"curr folder path{folder_path}")    
        if not os.path.isdir(folder_path):
            continue

        filenames = os.listdir(folder_path)
        for filename in filenames:
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path):
                if os.path.exists(os.path.join(args.output, f"{filename}_analysis.json")):
                    print(f"skip file:{filename}")
                    continue
                    
                try:
                    with open(file_path, "rb") as file_in_folder:
                        files = [("file", (filename, file_in_folder))]
                        r = requests.post(args.url, files=files, headers=header)
                        r.raise_for_status()
                        task_id = r.json()["task_id"]
                        task_ids.append((task_id, filename))
                        print(f"{filename} uploaded, task_id: {task_id}")
                except Exception as e:
                    print(f"error while upload {filename}: {str(e)}")

        with open(task_file, "w") as f:
            for task_id, filename in task_ids:
                print(f"write {task_id} at {task_file}")
                f.write(f"{task_id},{filename}\n")
        
        print("\nwait for analysis...")
        for task_id, filename in task_ids:
            while True:
                status = get_task_status(args.url, task_id, header)
                if status == "reported":
                    break
                elif status in ["failed", "error"]:
                    print(f"task{task_id} ({filename}) failed")
                    break
                print(f"wait for task {task_id} ({filename}) current status: {status}")
                time.sleep(30)
            
            if status == "reported":
                download_success = download_analysis_files(
                    args.url,
                    task_id,
                    filename,
                    args.output,
                    header
                )
                if not download_success:
                    print(f"some or all files download failed: task_id {task_id} ({filename})")

if __name__ == "__main__":
    main()
