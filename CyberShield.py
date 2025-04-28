import hashlib
import subprocess
from collections import namedtuple
import os
import pefile
import shutil
import time
from datetime import datetime
from colorama import Fore, Style, init
import json
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# Инициализация цветового оформления
init(autoreset=True)

# Функция для отображения ASCII-арта заголовка
def draw_title():
    title = """
     ____       ______     ________   _________  _________
    /\\  _`\\    /\\  ___\\   /\\  ___  \\ /\\___  ___\\/\\___  ___\\
    \\ \\ \\L\\ \\  \\ \\ \\__/   \\ \\ \\__/\\ \\\\/_/__/\\ \\//\\/__/\\ \\//
     \\ \\  _ <'  \\ \\___`\\   \\ \\ \\ \\ \\ \\   _\\ \\ \\     \\ \\ \\ 
      \\ \\ \\L\\ \\  \\/\\ \\L\\ \\  \\ \\ \\_\\ \\ \\ /\\ \\ \\ \\    \\_\\ \\ 
       \\ \\____/   \\ \\____/   \\ \\_____\\ \\\\ \\ \\_\\ \\   /\\_____\\
        \\/___/     \\/___/     \\/_____/  \\ \\/_/\\ \\  \\/_____/
                                           \\___\\/_/

                      CyberShield
    """
    print(title)

# Функция получения хэша файла с буферным чтением
def get_file_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as file:
        while chunk := file.read(4096):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Логирование результатов в формате JSON
def log_results(file_path, status, details=""):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "file_path": file_path,
        "status": status,
        "details": details
    }
    try:
        with open("scan_log.json", "a") as log_file:
            log_file.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"{Fore.YELLOW}Ошибка логирования: {e}")

# Сигнатурное сканирование файла
def scan_binary_file(file_path, virus_signatures):
    try:
        with open(file_path, "rb") as file:
            content = file.read()
            for signature in virus_signatures:
                if signature in content:
                    return True, f"{Fore.RED}Угрозы найдены: {signature.decode('utf-8', 'ignore')}"
        return False, f"{Fore.GREEN}Файл безопасен (сигнатурное сканирование)."
    except Exception as e:
        return False, f"{Fore.YELLOW}Ошибка: {e}"

# Анализ PE-файла
def analyze_pe_file(file_path, virus_signatures):
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            data = section.get_data()
            for signature in virus_signatures:
                if signature in data:
                    return True, f"{Fore.RED}Угрозы найдены в секции {section.Name.decode().strip()}: {signature.decode('utf-8', 'ignore')}"
        return False, f"{Fore.GREEN}Файл безопасен (PE-анализ)."
    except Exception as e:
        return False, f"{Fore.YELLOW}Ошибка анализа PE-файла: {e}"

# Функция перемещения файла в карантин
def quarantine_file(file_path):
    try:
        quarantine_path = os.path.join(os.getcwd(), "quarantine")
        os.makedirs(quarantine_path, exist_ok=True)
        quarantine_file_path = os.path.join(quarantine_path, os.path.basename(file_path))
        shutil.move(file_path, quarantine_file_path)
        print(f"{Fore.RED}Файл перемещён в карантин: {quarantine_file_path}")
        log_results(file_path, "Карантин", "Файл перемещён в карантин")
        analyze_quarantine_file(quarantine_file_path)
    except PermissionError:
        print(f"{Fore.YELLOW}Файл занят другим процессом. Попробуйте позже.")
    except Exception as e:
        print(f"{Fore.YELLOW}Ошибка при перемещении файла в карантин: {e}")

# Анализ файла в карантине
def analyze_quarantine_file(file_path):
    print(f"{Fore.BLUE}Начинаем полный анализ файла...")
    file_hash = get_file_hash(file_path)
    print(f"{Fore.CYAN}Хэш файла: {file_hash}")
    try:
        result = subprocess.run(['cmd', '/c', 'powershell', 'Get-MpComputerStatus'], capture_output=True, text=True)
        print(f"{Fore.CYAN}Статус системы: {result.stdout}")
    except Exception as e:
        print(f"{Fore.RED}Ошибка проверки системы: {e}")
    print(f"{Fore.GREEN}Анализ завершен.")

# Удаление файла из карантина
def delete_file_from_quarantine(file_name):
    quarantine_path = os.path.join(os.getcwd(), "quarantine")
    file_path = os.path.join(quarantine_path, file_name)

    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            print(f"{Fore.RED}Файл {file_name} успешно удалён из карантина.")
            log_results(file_path, "Удален", "Файл удалён из карантина")
        except Exception as e:
            print(f"{Fore.YELLOW}Ошибка при удалении файла: {e}")
    else:
        print(f"{Fore.RED}Файл {file_name} не найден в карантине.")

# Сканирование файла
def scan_file(file_path):
    virus_signatures = [
        b"keyboard.block_key",
        b"os.remove",
        b"SetWindowsHookExW",
        b"fullscreen",
        b"WM_DELETE_WINDOW",
        b"AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        b"AES",
        b"locked",
        b"CryptoKey",
        b"registry.disable",
        b"System.Reflection.Emit.AssemblyBuilder",
        b"token.stealer",
        b"Process Injection",
        b"payload.exe",
        b"Data\\Local\\Temp\\malware",
        b"Base64Decode",
        b"PowerShell.Invoke",
        b"screen.capture",
        b"clipboard.spy",
        b"ransomware",
        b"EncryptFile",
        b"malicious.command",
        b"network.scan",
        b"Backdoor.Win32",
        b"TrojanDownloader",
        b"unauthorized.access",
        b"CredentialDumping",
        b"reverse.shell",
        b"keystroke.logger",
        b"port.scan",
        b"botnet.command",
        b"malware.inject",
        b"phishing.page",
        b"DLLInjection",
        b"xor.encrypt",
        b"self_delete",
        b"virus.launcher",
        b"startup.modify",
        b"hook.handler",
        b"process.hollowing",
        b"powershell.download",
        b"malicious.payload",
        b"crypto.miner",
        b"exploit.kit",
        b"remote.admin.tool",
        b"WMIC.payload",
        b"admin.elevation",
        b"debug.disable",
        b"vulnerability.scanner",
        b"dump.credentials",
        b"network.packet",
        b"shellcode",
        b"PELoader",
        b"CodeCave",
        b"dynamic.unpacking",
        b"payload.dropper"
    ]
    print(f"{Fore.BLUE}Начинаю сканирование файла: {file_path}")
    time.sleep(1)
    is_suspicious, result = scan_binary_file(file_path, virus_signatures)
    print(result)
    if is_suspicious:
        quarantine_file(file_path)
        return
    if file_path.endswith(".exe"):
        is_suspicious, result = analyze_pe_file(file_path, virus_signatures)
        print(result)
        if is_suspicious:
            quarantine_file(file_path)
            return
    print(f"{Fore.GREEN}Файл прошёл проверку и безопасен.")

# Сканирование файлов с прогрессом
def scan_with_progress(file_paths):
    with tqdm(total=len(file_paths), desc="Сканирование файлов", unit="file") as pbar:
        for file_path in file_paths:
            scan_file(file_path)
            pbar.update(1)

# Функция отображения карантина
def list_quarantined_files():
    quarantine_path = os.path.join(os.getcwd(), "quarantine")
    if os.path.exists(quarantine_path):
        files = os.listdir(quarantine_path)
        print("\n".join(files) if files else "Карантин пуст.")
    else:
        print("Папка карантина отсутствует.")


# Функция для отображения инструкции
def show_instructions():
    instructions = """
    Добро пожаловать в CyberShield!
    Этот инструмент предназначен для сканирования файлов и выявления потенциально вредоносных данных.

    Основные функции:
    1. Сканирование одного файла – проверьте выбранный файл на угрозы.
    2. Сканирование нескольких файлов – загрузите несколько путей через запятую для проверки.
    3. Карантин – подозрительные файлы перемещаются в изолированную папку.
    4. Удаление из карантина – безопасно удалите файлы, которые вы считаете угрозой.
    5. Просмотр логов – узнайте результаты предыдущих сканирований.

    Инструкция:
    - Для сканирования укажите полный путь к файлу или файлам.
    - Карантин находится в папке "quarantine" внутри текущей директории программы.
    - Убедитесь, что вы обладаете правами доступа для перемещения или удаления файлов.
    - Логи сохраняются в файле "scan_log.json" для анализа результатов.

    Внимание:
    Данный инструмент является диагностическим и не заменяет полноценный антивирус. 
    Рекомендуется использовать в связке с другими средствами защиты.

    Удачной работы и берегите свои данные!
    """
    print(instructions)


# Обновление меню
def menu():
    while True:
        print(f"\n{Style.BRIGHT}{Fore.CYAN}--- CyberShield ---")
        print(f"{Fore.YELLOW}By Pytobegs")
        print(f"{Fore.CYAN}[1] Сканировать файл")
        print(f"{Fore.CYAN}[2] Сканировать несколько файлов")
        print(f"{Fore.CYAN}[3] Посмотреть карантин")
        print(f"{Fore.CYAN}[4] Удалить файл из карантина")
        print(f"{Fore.CYAN}[5] Посмотреть логи")
        print(f"{Fore.CYAN}[6] Инструкция")
        print(f"{Fore.CYAN}[7] Выйти\n")

        choice = input(f"{Fore.YELLOW}Выберите опцию: ")

        if choice == "1":
            file_path = input(f"{Fore.YELLOW}Введите путь к файлу: ")
            if os.path.exists(file_path):
                scan_file(file_path)
            else:
                print(f"{Fore.RED}Файл не найден. Проверьте путь.")
        elif choice == "2":
            file_paths = input(f"{Fore.YELLOW}Введите пути к файлам через запятую: ").split(",")
            file_paths = [path.strip() for path in file_paths if os.path.exists(path.strip())]
            if file_paths:
                scan_with_progress(file_paths)
            else:
                print(f"{Fore.RED}Нет корректных путей для сканирования.")
        elif choice == "3":
            list_quarantined_files()
        elif choice == "4":
            file_name = input(f"{Fore.YELLOW}Введите имя файла для удаления из карантина: ")
            delete_file_from_quarantine(file_name)
        elif choice == "5":
            print(f"{Fore.BLUE}Логи сканирования:")
            if os.path.exists("scan_log.json"):
                with open("scan_log.json", "r") as log_file:
                    print(log_file.read())
            else:
                print(f"{Fore.RED}Лог файл отсутствует.")
        elif choice == "6":
            show_instructions()
        elif choice == "7":
            print(f"{Fore.GREEN}Выход из программы...")
            break
        else:
            print(f"{Fore.RED}Неверный ввод. Попробуйте снова.")


# Запуск программы
draw_title()
show_instructions()
menu()

