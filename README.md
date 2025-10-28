
<div align="center">

```
  _____                                   _      _____                _   _             
 |  __ \                                 | |    / ____|              | | (_)            
 | |__) | __ ___   __ _ _ __ __ _ _ __ ___| |   | (___   ___ _ __ __ _| |_ _  ___  _ __  
 |  _  / '__/ _ \ / _` | '__/ _` | '_ ` _ \| |    \___ \ / __| '__/ _` | __| |/ _ \| '_ \ 
 | | \ \| | | (_) | (_| | | | (_| | | | | | | |    ____) | (__| | | (_| | |_| | (_) | | | |
 |_|  \_\_|  \___/ \__, |_|  \__,_|_| |_| |_|_|   |_____/ \___|_|  \__,_|\__|_|\___/|_| |_|
                  __/ |                                                                
                 |___/                                                                 
```

### Ferramenta Educacional para Análise de Ransomware

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![C](https://img.shields.io/badge/C-11-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Completo-brightgreen.svg)
![Purpose](https://img.shields.io/badge/Propósito-Educacional-orange.svg)

</div>

> ⚠️ **AVISO LEGAL CRÍTICO**
> 
> Este projeto é **EXCLUSIVAMENTE PARA FINS EDUCACIONAIS** e deve ser utilizado em um **ambiente controlado e isolado** (como uma Máquina Virtual). O uso deste código em sistemas reais ou para fins maliciosos é **ILEGAL** e pode constituir crime federal. **NÃO ME RESPONSABILIZO POR USO INDEVIDO DESTE CÓDIGO.**

---

## 🚀 Sobre o Projeto

Este é um ransomware educacional avançado que demonstra o ciclo de vida e as táticas de ataques modernos. O código é modular e integra um payload em **C** para simular técnicas de baixo nível, oferecendo uma visão realista da arquitetura de um malware sofisticado.

O objetivo é ensinar sobre:

-   Criptografia híbrida (RSA + AES-GCM)
-   Técnicas de evasão, persistência e exfiltração de dados
-   Estrutura de malware modular e profissional
-   Interoperabilidade entre Python e C (`ctypes`)

---

## ✨ Funcionalidades Simuladas

Este projeto simula de forma segura um ataque de ransomware em várias fases:

#### 1. Evasão e Preparação
-   **Execução de Payload C**: Carrega e executa uma DLL em C para simular táticas de evasão e ofuscação.
-   **Elevação de Privilégio (UAC)**: Simula um pop-up de UAC para obter acesso de administrador.
-   **Detecção de VM**: Verifica se está rodando em um ambiente virtual para evitar análise.
-   **Evasão de Defesa**: Simula a finalização de processos de antivírus.

#### 2. Infiltração e Persistência
-   **Exfiltração de Dados**: Simula a busca e o roubo de arquivos com nomes "sensíveis".
-   **Comunicação C&C**: Simula o envio da chave de criptografia e da lista de arquivos para o servidor do atacante.
-   **Persistência**: Garante a re-execução após reinicialização através de uma Tarefa Agendada.

#### 3. Ação no Alvo
-   **Seleção Abrangente de Alvos**: Varre todos os perfis de usuário e drives fixos, ignorando pastas de sistema.
-   **Exclusão de Backups**: Simula a exclusão de Cópias de Sombra (Shadow Copies) do Windows.
-   **Criptografia Forte**: Utiliza AES-256-GCM para bloquear os arquivos e RSA-4096 para proteger a chave.

---

## 📈 Diagrama do Fluxo de Ataque

```mermaid
graph TD
    A[Início da Execução] --> B[Executa Payload C (DLL)];
    B --> C{Verifica Admin?};
    C -- Não --> D[Simula UAC Prompt];
    D --> E{Usuário Clicou 'Sim'?};
    E -- Sim --> F[Eleva Privilégios (Simulado)];
    E -- Não --> G[Continua com Privilégios Limitados];
    C -- Sim --> F;
    F --> H[Simula Finalização de AV];
    G --> H;
    H --> I[Simula Exfiltração de Dados];
    I --> J[Simula Exclusão de Shadow Copies];
    J --> K[Cria Persistência];
    K --> L[Varre Drives e Usuários];
    L --> M[Criptografa Arquivos];
    M --> N[Fim do Ataque];
```

---

## 🛠️ Instalação e Uso

### Requisitos
-   **Sistema Operacional**: Windows (para todas as simulações), macOS/Linux (funcionalidade limitada)
-   **Compilador C**: `gcc` (recomendado via [MinGW-w64](https://www.mingw-w64.org/)) para compilar o payload.
-   **Dependências Python**:
    ```bash
    Python 3.8+
    cryptography>=41.0.0
    requests
    psutil
    ```

### Passos para Instalação
1.  **Clone o projeto:**
    ```bash
    git clone <URL_DO_REPOSITORIO>
    cd ransomware-analysis-toolkit-main
    ```
2.  **Compile o Payload C:**
    *   Certifique-se de ter o `gcc` instalado e no PATH do seu sistema.
    *   Execute o comando de compilação no diretório raiz do projeto:
    ```bash
    gcc -shared -o payload.dll payload.c
    ```
3.  **Crie um ambiente virtual e instale as dependências:**
    ```bash
    python -m venv venv
    # No Windows:
    venv\Scripts\activate
    # No macOS/Linux:
    source venv/bin/activate
    
    pip install -r requirements.txt # Supondo que você crie um requirements.txt
    # Ou manualmente:
    pip install cryptography requests psutil
    ```

### Comandos
-   **Criar ambiente de teste:**
    ```bash
    python main.py --setup
    ```
-   **Simular o ataque completo:**
    ```bash
    python main.py --encrypt
    ```
-   **Recuperar os arquivos:**
    ```bash
    python main.py --decrypt
    ```

---

## ⚙️ Detalhes Técnicos

<details>
<summary><strong>Estrutura dos Arquivos</strong></summary>

```
ransomware-analysis-toolkit-main/
├── ransomware/
│   ├── __init__.py
│   ├── core.py         # Classe principal do ransomware
│   ├── config.py       # Configurações (extensões, pastas a excluir)
│   └── utils.py        # Funções de simulação e utilitários
├── payload.c           # Código fonte do payload de baixo nível
├── payload.dll         # Biblioteca compilada (após compilação)
├── main.py             # Ponto de entrada da aplicação
├── test_files/         # Diretório de teste (criado com --setup)
└── README.md           # Este arquivo
```

</details>

<details>
<summary><strong>Algoritmos de Criptografia</strong></summary>

| Componente               | Algoritmo     | Tamanho   | Propósito                  |
| ------------------------ | ------------- | --------- | -------------------------- |
| Chave Mestre             | RSA           | 4096 bits | Proteger a chave de sessão |
| Criptografia de Arquivos | AES-GCM       | 256 bits  | Criptografar o conteúdo    |
| Derivação de Chave       | PBKDF2-SHA256 | 256 bits  | Chave única por arquivo    |
| Autenticação de Dados    | GCM Tag       | 128 bits  | Garantir a integridade     |

</details>

---

## 📚 Objetivos Educacionais e Recursos

Este projeto é uma ferramenta poderosa para aprender sobre segurança ofensiva e defensiva.

<details>
<summary><strong>Clique para ver os Recursos de Estudo</strong></summary>

### Livros Recomendados
-   "Malware Data Science" - Joshua Saxe
-   "Practical Malware Analysis" - Michael Sikorski
-   "The Art of Memory Forensics" - Michael Hale Ligh

### Cursos
-   SANS FOR610: Reverse-Engineering Malware
-   eLearnSecurity eMAPT
-   Offensive Security OSEP

### Plataformas de Prática
-   TryHackMe (Salas de Análise de Malware)
-   HackTheBox (Desafios de Forense)
-   MalwareBazaar (Amostras reais de malware)

</details>

---

## ⚖️ Aspectos Legais e Uso Responsável

<details>
<summary><strong>Clique para ver os detalhes legais (Lei 12.737/2012 e 14.155/2021)</strong></summary>

### Lei 12.737/2012 (Lei Carolina Dieckmann)
-   **Art. 154-A**: Invasão de dispositivo informático. Pena: 3 meses a 1 ano + multa.
-   **Agravantes**: Prejuízo econômico, roubo de dados sensíveis, etc.

### Lei 14.155/2021 (Crimes Cibernéticos)
-   Alterou o Código Penal para incluir furto, estelionato e fraude eletrônica.

**DISTRIBUIR OU USAR ESTE CÓDIGO PARA FINS MALICIOSOS É CRIME.**

</details>

### ✅ Permitido:
-   Estudar o código em ambiente isolado (VM).
-   Usar para pesquisa acadêmica e apresentações.
-   Aprender sobre criptografia e táticas de malware.

### ❌ Proibido:
-   Usar em sistemas de terceiros, sem autorização.
-   Distribuir sem o contexto educacional.
-   Modificar para criar um malware real.

---

<div align="center">

**Lembre-se: com grande conhecimento vem grande responsabilidade. Use este código para o bem!**

*Desenvolvido para fins educacionais | 2025*

</div>
