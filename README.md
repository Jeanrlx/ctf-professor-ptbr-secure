# CTF Professor 🎓🛡️

> **Um mentor de cibersegurança que ensina você a pensar, no terminal onde o trabalho acontece.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Language: PT-BR](https://img.shields.io/badge/Idioma-PT--BR-009c3b)](README.md)
[![Language: EN](https://img.shields.io/badge/Language-EN-blue)](README.md)
[![Powered by Claude Code](https://img.shields.io/badge/Powered%20by-Claude%20Code-blueviolet)](https://claude.ai/code)

O **CTF Professor** é um sistema de agentes de IA focado no ensino de cibersegurança através de desafios de CTF. Roda diretamente no seu terminal via **Claude Code** — sem npm, sem dependências externas, com isolamento real via Docker.

---

## 🚀 Quick Start

### 1. Pré-requisitos

- **Docker** instalado e rodando
- **Python 3.8+** e **Git**
- **Claude Code** (`claude` no terminal — já instalado se você está lendo isso aqui)

### 2. Instalação

```powershell
git clone https://github.com/Jeanrlx/ctf-professor-ptbr-secure.git
cd ctf-professor-ptbr-secure

# Instale as dependências Python do MCP server
pip install -r requirements.txt

# Construa a imagem Docker do sandbox Kali Linux
docker build -t cyber-ctf-kali .agent/sandbox/
```

### 3. Inicie o Claude Code no projeto

```powershell
cd ctf-professor-ptbr-secure
claude
```

O Claude Code carrega automaticamente:
- `CLAUDE.md` — regras dos agentes e comportamento pedagógico
- `.claude/settings.json` — servidor MCP do sandbox Docker

### 4. Configure o ambiente (primeira vez)

```
/install
```

Verifica Docker, Python, ferramentas locais e vincula plataformas CTF (opcional).

### 5. Comece a aprender

1. Crie uma pasta em `CTFs/` para o seu desafio (ex: `CTFs/meu-pwn/`)
2. Coloque os arquivos do desafio lá dentro
3. No Claude Code, inicie:

```
/start-ctf meu-pwn
```

Você também pode passar uma URL de CTFd, HackTheBox ou TryHackMe diretamente:

```
/start-ctf https://app.hackthebox.com/challenges/123
```

---

## Comandos Disponíveis

| Comando | O que faz |
|:---|:---|
| `/install` | Configura o ambiente, Docker e plataformas CTF |
| `/start-ctf [pasta\|url\|descrição]` | Inicia sessão com classificação obrigatória |
| `/hint` | Dica socrática progressiva (3 níveis) |
| `/classify-challenge` | Classifica sem resolver |
| `/analyze-binary` | Pipeline completo de análise estática + dinâmica |
| `/explain-vulnerability` | Explicação educacional de uma vulnerabilidade |
| `/writeup [pasta]` | Gera writeup profissional com análise STRIDE |
| `/list-ctf` | Lista desafios locais na pasta `CTFs/` |
| `/link-ctf` | Vincula conta de plataforma CTF |

---

## Recursos

- **Sandbox Docker Seguro**: Ferramentas agressivas (nmap, gdb, sqlmap, pwntools) rodam dentro de um container Kali Linux isolado — nunca no seu host Windows
- **Hardening aplicado**: Container não-root, perfil seccomp customizado, capabilities mínimas, validação de comandos contra injection
- **Fluxo Pedagógico de 2 Passos**: O agente avalia sua metodologia antes de executar ferramentas
- **Bilíngue**: Detecta PT-BR/EN automaticamente por mensagem
- **Integração com Plataformas**: CTFd, HackTheBox e TryHackMe
- **Geração de Writeups**: Documentação profissional com impacto corporativo e mitigação STRIDE

---

## Arquitetura

```
.
├── CLAUDE.md                    ← Regras e comportamento dos agentes (carregado automaticamente)
├── .claude/settings.json        ← Configuração MCP do sandbox
├── .agent/
│   ├── agents/                  ← 19 agentes especializados
│   ├── skills/                  ← 28 módulos de habilidade
│   ├── workflows/               ← 13 slash commands
│   ├── sandbox/
│   │   ├── Dockerfile           ← Kali Linux (usuário não-root, tools CTF)
│   │   └── seccomp-ctf.json     ← Perfil seccomp customizado
│   └── scripts/
│       ├── sandbox_manager.py   ← Gerenciamento do container Docker
│       ├── sandbox_mcp.py       ← Servidor MCP (expõe sandbox ao Claude)
│       └── install_setup.py     ← Setup automático
├── CTFs/                        ← Seus desafios locais
└── requirements.txt             ← mcp, fastmcp, pwntools, requests
```

---

## Segurança do Sandbox

O container Docker foi endurecido contra os principais vetores de ataque:

| Proteção | Implementação |
|:---|:---|
| Usuário não-root | `ctfuser` com sudo restrito a 4 ferramentas |
| Seccomp customizado | Bloqueia 30+ syscalls de escape de container |
| Capabilities mínimas | `--cap-drop=ALL` + re-adição seletiva |
| Filesystem read-only | Root FS somente leitura; `/tmp` em tmpfs |
| Validação de comandos | Blocklist de 14 padrões perigosos antes de `docker exec` |
| Rate limiting MCP | 20 chamadas/60 segundos |

---

## Mantenedor

**[Jean Rodrigues](https://www.linkedin.com/in/imjeanrodrigues)** — [@Jeanrlx](https://github.com/Jeanrlx)

---

## Créditos

- Projeto original: [magalz/ctf-professor-ptbr](https://github.com/magalz/ctf-professor-ptbr)
- Framework base: [vudovn/antigravity-kit](https://github.com/vudovn/antigravity-kit)
- Fork com hardening de segurança e adaptação para Claude Code: [Jeanrlx](https://github.com/Jeanrlx)

---

## Licença

MIT — Livre para usar, aprender e contribuir.
