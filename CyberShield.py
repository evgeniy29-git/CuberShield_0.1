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
   virus_signatures = [#275 сигнатур
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
        b"payload.dropper",
        b"obfuscation.technique",
        b"malicious.script",
        b"exploit.remote",
        b"heap.spray",
        b"buffer.overflow",
        b"kernel.exploit",
        b"process.tampering",
        b"rootkit.install",
        b"keylogging.activity",
        b"hidden.process",
        b"anti.debugging",
        b"packer.detected",
        b"stealth.technique",
        b"code.injection",
        b"privilege.escalation",
        b"system.backdoor",
        b"browser.hijack",
        b"malicious.url",
        b"command.and.control",
        b"persistence.mechanism",
        b"zero.day.exploit",
        b"hidden.registry.entry",
        b"hidden.startup.script",
        b"remote.thread.execution",
        b"encrypted.communication",
        b"rogue.process",
        b"anti.sandbox",
        b"remote.keylogger",
        b"malicious.batch.script",
        b"script.obfuscation",
        b"stealthy.communication",
        b"trojan.behavior",
        b"malicious.shellcode",
        b"auto.execution",
        b"hooked.dll",
        b"undetectable.payload",
        b"fake.error.message",
        b"hidden.network.request",
        b"unknown.executable",
        b"anti.forensics",
        b"browser.exploit",
        b"crypto.wallet.stealer",
        b"malicious.driver",
        b"undocumented.api.calls",
        b"trojan.rootkit",
        b"hidden.file",
        b"memory.dump",
        b"network.exfiltration",
        b"bypass.uac",
        b"code.execution",
        b"dynamic.code.loading",
        b"hidden.tunnel",
        b"malicious.websocket",
        b"fake.certificate",
        b"anti.av.evade",
        b"usb.infector",
        b"hidden.network.share",
        b"registry.tampering",
        b"persistence.inject",
        b"stealth.mode",
        b"dropper.script",
        b"malicious.macro",
        b"exfiltrated.data",
        b"undocumented.process",
        b"tampered.permission",
        b"worm.spreading",
        b"malware.heuristic",
        b"network.eavesdropping",
        b"security.bypass",
        b"api.hooking",
        b"ransomware.variant",
        b"command.shell.access",
        b"privilege.abuse",
        b"stealthy.trojan",
        b"system.corruption",
        b"kernel.rootkit",
        b"malicious.scheduled.task",
        b"process.injection.technique",
        b"dark.web.connection",
        b"malicious.telemetry",
        b"hardware.keylogger",
        b"undetectable.exploit",
        b"process.manipulation",
        b"unusual.network.activity",
        b"firewall.bypass",
        b"advanced.persistence",
        b"hidden.trojan",
        b"crypto.ransomware",
        b"data.exfiltration",
        b"browser.redirect",
        b"web.inject",
        b"malicious.asm",
        b"network.proxy.abuse",
        b"hidden.api.calls",
        b"fake.updates",
        b"phishing.redirection",
        b"malicious.dll",
        b"auto.rootkit.install",
        b"server.exploit",
        b"hidden.backdoor",
        b"anti.virtual.machine",
        b"undetectable.shellcode",
        b"trojan.variant",
        b"crypto.theft",
        b"memory.inject",
        b"malware.unpacker",
        b"browser.manipulation",
        b"system.exploit",
        b"hidden.service",
        b"credential.harvesting",
        b"network.spreader",
        b"web.keylogger",
        b"bootkit",
        b"malicious.dns.query",
        b"hidden.websocket",
        b"persistent.payload",
        b"encrypted.keylogger",
        b"malicious.file.dropper",
        b"advanced.evasion.technique",
        b"live.off.the.land.attack",
        b"remote.shell.access",
        b"password.stealer",
        b"network.hijacking",
        b"exploit.chain",
        b"fake.antivirus",
        b"drive.by.download",
        b"rootkit.persistence",
        b"malicious.chrome.extension",
        b"malicious.edge.extension",
        b"malicious.firefox.addon",
        b"zero.click.exploit",
        b"malware.loader",
        b"attack.vector.expansion",
        b"browser.exploit.chain",
        b"malicious.powershell.module",
        b"stealth.persistence",
        b"auto.execute.script",
        b"malicious.font.inject",
        b"exploit.obfuscation",
        b"browser.session.hijacking",
        b"wifi.exploit",
        b"firmware.tampering",
        b"hardware.exploit",
        b"network.packet.tampering",
        b"hidden.keylogging.module",
        b"undetected.backdoor",
        b"crypto.api.abuse",
        b"malicious.remote.updater",
        b"kernel.memory.patch",
        b"malicious.vba.macro",
        b"registry.persistence",
        b"hidden.process.injection",
        b"malware.auto.spread",
        b"trojanized.software",
        b"malicious.dll.hijacking",
        b"malicious.service.creation",
        b"undetectable.injector",
        b"malicious.system.modification",
        b"hidden.ransomware",
        b"malware.encryption.engine",
        b"stealthy.data.theft",
        b"browser.exploit.variant",
        b"packet.interceptor",
        b"malicious.window.manager",
        b"network.c2.communication",
        b"hidden.domain.request",
        b"exploit.with.auto.execution",
        b"process.suspend",
        b"process.kill",
        b"stealth.backdoor",
        b"crypto.stealer",
        b"malicious.registry.write",
        b"hidden.file.creation",
        b"remote.admin.abuse",
        b"hidden.data.transmission",
        b"network.tunneling",
        b"browser.injection",
        b"malicious.startup.entry",
        b"system.disable",
        b"unusual.api.call",
        b"encrypted.malware.loader",
        b"malicious.websocket.connection",
        b"network.packet.manipulation",
        b"obfuscated.network.request",
        b"targeted.payload",
        b"unauthorized.data.extraction",
        b"malicious.web.inject",
        b"browser.hijacking.attempt",
        b"fake.certificate.install",
        b"malware.remote.control",
        b"undetected.exploit.variant",
        b"hidden.script.execution",
        b"malicious.thread.hijack",
        b"memory.tampering",
        b"crypto.miner.installation",
        b"malicious.system.interceptor",
        b"backdoor.persistence",
        b"obfuscated.shell.execution",
        b"browser.plugin.exploit",
        b"cloaked.network.activity",
        b"malicious.kernel.modification",
        b"exploit.automation",
        b"malicious.script.inject",
        b"process.hiding",
        b"remote.surveillance",
        b"malware.camouflage",
        b"deceptive.execution",
        b"unauthorized.encryption",
        b"security.feature.bypass",
        b"malicious.driver.install",
        b"kernel.access.exploit",
        b"encrypted.stealthy.payload",
        b"network.manipulation",
        b"multi.stage.exploit",
        b"malicious.cookie.theft",
        b"fileless.malware",
        b"malicious.patch.inject",
        b"remote.file.creation",
        b"hidden.system.modification"
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

