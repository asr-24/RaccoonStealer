import os 
import memdump
import pandas as pd

import fileHashing as fH

from datetime import datetime

def timestamp ():
    now = datetime.now() 
    print("now =", now)
    # dd/mm/YY H:M:S
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    return dt_string

timestamp_list = []
detection_type_list = []
file_path_list = []
hex_offset_list = []
found_suspicious_entry_list = []
IOC_hash_list = []
known_file_marker = []

def log_function ():
    
    logs = {}

    logs['TimeStamp'] = timestamp_list
    logs['DetectionType'] = detection_type_list
    logs['FilePath'] = file_path_list
    logs['HexOffset'] = hex_offset_list
    logs['FoundSuspiciousEntry'] = found_suspicious_entry_list
    logs['IOC'] = IOC_hash_list
    logs['KnownFileMarker'] = known_file_marker
    
    write_data = pd.DataFrame.from_dict(logs)
    
    write_data.to_excel("test_results.xlsx")
    



sus_exe = ["iexpxlore.exe", "powershell.exe", "zgrsxzd4.tmp", "outlook.exe", "winword.exe", "evauvjh.exe", "evauvjh.exe", "cmd.exe", "ping.exe", "Firefall Installer.exe", "Installer.exe", "Setup.exe", "setup.exe", "binary.exe", "Setupshort.exe", "payload.exe", "111.exe", "daemon.exe", "streamix.exe", "asdfg.exe", "NFT.exe", "rlm.foundry.exe", "okok.exe", "2.0.2-beta2.exe", "readme.bin.exe", "zxc.exe"]

sus_dll = ["nss3.dll","msvcp140.dll", "vcruntime140.dll", "mozglue.dll", "freebl3.dll", "softtokn3.dll", "sqlite3.dll", "nssdbm3.dll"]


print("Starting recursive directory searches in all folder on the PC...")
print("This will take some time. Do not stop the program or let the PC go in standby/sleep modes.\n\n\n")


paths = []

ignore_list = [b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/']

all_drives = ["C:\\", "D:\\", "E:\\", "F:\\"] 

try:
    for drive in all_drives:
        print(drive)
        try:
            file_names = []
            for root,d_names,f_names in os.walk(drive):
            	for f in f_names:
            		file_names.append(os.path.join(root, f))
            for i in range(len(file_names)):
                file = file_names[i]
                if (file.endswith(".dll") or file.endswith(".exe")):
                    print(os.path.join(file))
                    try:
                        result_of_scan = memdump.main(file)
                        if (len(result_of_scan)!=3 or result_of_scan[2] in ignore_list):
                            continue
                        else:
                            timestamp_list.append(timestamp())
                            file_path_list.append(os.path.join(file))
                            detection_type_list.append(result_of_scan[0])
                            hex_offset_list.append(result_of_scan[1])
                            found_suspicious_entry_list.append(result_of_scan[2])
                            IOC_hash_list.append(fH.hashing_function(os.path.join(file)))
                            if (file in sus_exe or file in sus_dll):
                                known_file_marker.append('True')
                            else:
                                known_file_marker.append('-')
                                         
                        print("\n\n\n")
                    except Exception as ex:
                        print(f"here[!] exception: {ex}")
                    
                else:
                    completion = round(i*100/len(file_names), 4)
                    print(f'\t\t\t\t\tCompleted {completion}%')
            
        except FileNotFoundError as e:
            print(f"**Directory missing {e}**")
    
        log_function()
    

except KeyboardInterrupt or ValueError:  
    log_function()
    

    
# https://developers.virustotal.com/reference/files-scan