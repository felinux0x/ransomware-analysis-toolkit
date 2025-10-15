# Ransomware Educacional Avançado

!Python
!License
!Status

> **AVISO LEGAL CRÍTICO**
> 
> Este projeto é **EXCLUSIVAMENTE PARA FINS EDUCACIONAIS** em ambiente controlado. 
> O uso deste código em sistemas reais ou para fins maliciosos é **CRIME FEDERAL** previsto na Lei 12.737/2012 (Lei Carolina Dieckmann).
> 
> **NÃO ME RESPONSABILIZO POR USO INDEVIDO DESTE CÓDIGO.**

## Sobre o Projeto

Este é um ransomware educacional desenvolvido em Python para demonstrar como funciona a criptografia de arquivos em ataques de ransomware modernos. O objetivo é ensinar sobre:

- Criptografia híbrida (RSA + AES)
- Técnicas de derivação de chaves
- Multi-threading para performance
- Authenticated encryption (GCM)
- Estrutura de malware real

## Recursos Implementados

### Criptografia de Nível Militar
- **RSA-4096**: Criptografia assimétrica para proteger a chave mestre
- **AES-256-GCM**: Criptografia simétrica com autenticação
- **PBKDF2**: Derivação única de chave para cada arquivo (100.000 iterações)

### Performance Otimizada
- **Multi-threading**: 4 threads simultâneas para criptografia paralela
- **Processamento em lote**: Criptografa múltiplos arquivos de uma vez
- **Métricas de performance**: Velocidade e tempo de execução

### Recursos Avançados
- **Session ID único**: Cada "infecção" tem identificador único
- **Logging completo**: Registra todos os arquivos criptografados
- **Notas de resgate**: Múltiplas notas em HTML e TXT
- **Extensões alvo**: 20+ tipos de arquivos críticos

## Requisitos

### Sistema Operacional
- Linux (Testado no Mint/Ubuntu)
- Windows (compatível)
- macOS (compatível)

### Dependências
```bash
Python 3.8+
cryptography>=41.0.0
```

## Instalação

### 1. Clone ou copie o projeto
```bash
mkdir ransomware-edu
cd ransomware-edu
# Cole o arquivo main.py aqui
```

### 2. Crie um ambiente virtual (RECOMENDADO)
```bash
python3 -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate
```

### 3. Instale as dependências
```bash
pip install cryptography
```

## Uso

### Passo 1: Criar Ambiente de Teste
```bash
python main.py --setup
```
Isso criará:
- Diretório `test_files/` com 4 subdiretórios
- 7 arquivos de teste em diferentes formatos
- Ambiente isolado e seguro para testes

### Passo 2: Criptografar Arquivos (Simular Ataque)
```bash
python main.py --encrypt
```
O que acontece:
- Gera par de chaves RSA-4096
- Cria chave de sessão AES-256
- Criptografa todos os arquivos alvo
- Adiciona extensão com Session ID
- Cria notas de resgate
- Exibe estatísticas de performance

### Passo 3: Descriptografar Arquivos (Recuperação)
```bash
python main.py --decrypt
```
O que acontece:
- Carrega as chaves RSA e de sessão
- Descriptografa todos os arquivos
- Restaura nomes originais
- Remove arquivos de controle
- Exibe estatísticas de recuperação

## Estrutura de Arquivos

```
ransomware-edu/
├── main.py                          # Script principal
├── venv/                            # Ambiente virtual (após instalação)
├── test_files/                      # Diretório de teste (após --setup)
│   ├── documents/
│   ├── images/
│   ├── data/
│   ├── code/
│   └── !!!RANSOM_NOTE!!!.txt       # Nota de resgate (após --encrypt)
├── master_private.key               # Chave privada RSA (após --encrypt)
├── .key_XXXX.enc                   # Chave de sessão criptografada
├── .log_XXXX.json                  # Log de arquivos criptografados
└── README.md                        # Este arquivo
```

## Detalhes Técnicos

### Algoritmos Utilizados

| Componente | Algoritmo | Tamanho | Propósito |
|------------|-----------|---------|-----------|
| Chave Mestre | RSA | 4096 bits | Proteger chave de sessão |
| Criptografia de Arquivos | AES-GCM | 256 bits | Criptografar conteúdo |
| Derivação de Chave | PBKDF2-SHA256 | 256 bits | Chave única por arquivo |
| Autenticação | GCM Tag | 128 bits | Integridade dos dados |

### Fluxo de Criptografia

```
1. Gerar par RSA-4096 (pública/privada)
2. Gerar chave mestre AES-256 aleatória
3. Criptografar chave mestre com RSA público
4. Para cada arquivo:
   a. Derivar chave única usando PBKDF2(master_key + filepath)
   b. Gerar IV aleatório (16 bytes)
   c. Criptografar com AES-256-GCM
   d. Salvar: IV + Tag + Ciphertext
   e. Renomear arquivo com extensão .SESSION_ID
5. Gerar notas de resgate
```

### Extensões Alvo

```python
['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx',
 '.ppt', '.pptx', '.jpg', '.jpeg', '.png', '.gif',
 '.zip', '.rar', '.sql', '.csv', '.json', '.xml',
 '.html', '.css', '.js', '.py', '.java', '.cpp']
```

## Objetivos Educacionais

### O que você aprenderá:

1. **Criptografia Moderna**
   - Como RSA e AES trabalham juntos
   - Por que criptografia híbrida é usada
   - Importância de authenticated encryption

2. **Segurança Ofensiva**
   - Estrutura de malware real
   - Técnicas de evasão (arquivos ocultos)
   - Multi-threading para performance

3. **Segurança Defensiva**
   - Como detectar atividades suspeitas
   - Importância de backups
   - Mitigação de ransomware

4. **Programação Python**
   - Threading e concorrência
   - Manipulação de arquivos
   - Criptografia com cryptography

## Proteção Contra Ransomware

### Boas Práticas:

1. **Backups Regulares**
   - Backup 3-2-1: 3 cópias, 2 mídias diferentes, 1 offsite
   - Testar restauração regularmente

2. **Segurança em Camadas**
   - Antivírus atualizado
   - Firewall configurado
   - EDR (Endpoint Detection and Response)

3. **Treinamento de Usuários**
   - Não abrir anexos suspeitos
   - Verificar remetentes de emails
   - Reportar atividades suspeitas

4. **Atualizações**
   - Sistema operacional sempre atualizado
   - Patches de segurança aplicados
   - Software mantido atualizado

## Análise de Malware

### Como Analisar Este Código:

```bash
# 1. Ambiente Isolado (VM ou Container)
docker run -it --rm python:3.9 bash

# 2. Análise Estática
strings main.py | grep -E "(key|encrypt|crypto)"

# 3. Análise Dinâmica
strace -o trace.txt python main.py --encrypt

# 4. Monitoramento de Arquivos
inotifywait -m -r test_files/
```

## Limitações (Intencional para Segurança)

Este código **NÃO** implementa:

- Persistência no sistema
- Comunicação C&C (Command & Control)
- Técnicas anti-análise avançadas
- Exclusão de shadow copies
- Propagação em rede
- Privilégios elevados (UAC bypass)
- Criptografia de MBR/Boot

Essas funcionalidades foram **intencionalmente omitidas** para prevenir uso malicioso.

## Recursos para Estudo

### Livros Recomendados:
- "Malware Data Science" - Joshua Saxe
- "Practical Malware Analysis" - Michael Sikorski
- "The Art of Memory Forensics" - Michael Hale Ligh

### Cursos:
- SANS FOR610: Reverse-Engineering Malware
- eLearnSecurity eMAPT
- Offensive Security OSEP

### Plataformas de Prática:
- TryHackMe (Malware Analysis rooms)
- HackTheBox (Forensics challenges)
- MalwareBazaar (amostras reais)

## Aspectos Legais

### Lei 12.737/2012 (Lei Carolina Dieckmann)

**Art. 154-A**: Invasão de dispositivo informático
- Pena: 3 meses a 1 ano + multa

**Agravantes** (Art. 154-A, §4º):
- Prejuízo econômico: até 5 anos
- Dados sensíveis: até 5 anos
- Fins lucrativos: até 5 anos

### Lei 14.155/2021 (Crimes Cibernéticos)

Alterou o Código Penal incluindo:
- Furto e estelionato eletrônico
- Fraude eletrônica
- Invasão de dispositivos

**DISTRIBUIR OU USAR RANSOMWARE É CRIME!**

## Uso Responsável

### Permitido:
- Estudar o código em ambiente isolado
- Testar em VMs pessoais
- Usar para pesquisa acadêmica
- Ensinar sobre segurança

### PROIBIDO:
- Usar em sistemas de terceiros
- Distribuir sem contexto educacional
- Modificar para uso malicioso
- Executar em ambiente corporativo sem autorização

## Troubleshooting

### Erro: "No module named 'cryptography'"
```bash
pip install cryptography
```

### Erro: "Permission denied"
```bash
chmod +x main.py
```

### Arquivos não descriptografam
```bash
# Verifique se as chaves existem
ls -la | grep -E "(master_private|\.key_|\.log_)"

# Verifique o Session ID
cat .log_*.json | grep session_id
```

## Contato

**Apenas para fins educacionais e acadêmicos!**

Para questões sobre segurança ofensiva/defensiva, consulte:
- CERT.br: https://cert.br
- OWASP: https://owasp.org
- SANS Institute: https://sans.org

## Licença

Este projeto é fornecido "como está", para fins educacionais apenas.

**MIT License** - Veja LICENSE para mais detalhes.

---

## Conclusão

Este projeto demonstra a sofisticação de ransomware moderno e serve como ferramenta educacional para:

- Estudantes de segurança da informação
- Pesquisadores de malware
- Profissionais de Blue Team
- Entusiastas de criptografia

**Lembre-se**: Com grande conhecimento vem grande responsabilidade. Use este código apenas para o bem!

---

*Desenvolvido para fins educacionais | 2025*