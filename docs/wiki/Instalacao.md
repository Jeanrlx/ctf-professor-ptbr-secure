# ⚙️ Guia de Instalação e Configuração

Configurar o **CTF Professor** é um processo simples com poucos pré-requisitos.

## 🛠️ Pré-requisitos

| Ferramenta | Instalação |
|:---|:---|
| **Claude Code** | `npm install -g @anthropic-ai/claude-code` |
| **Docker** | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) ou Docker Engine no Linux |
| **Python 3.8+** | [python.org](https://www.python.org/) |
| **Git** | [git-scm.com](https://git-scm.com/) |

---

## 🚀 Instalação (Linux/Kali recomendado)

```bash
# 1. Clonar o repositório
git clone https://github.com/Jeanrlx/ctf-professor-ptbr-secure.git
cd ctf-professor-ptbr-secure

# 2. Instalar dependências Python do MCP server
pip install -r requirements.txt

# 3. Construir a imagem Docker do sandbox Kali Linux
docker build -t cyber-ctf-kali .agent/sandbox/

# 4. Iniciar o Claude Code
claude
```

Dentro do Claude Code, rode a configuração automática:
```
/install
```

---

## O que o `/install` faz automaticamente?

1. **Sonda o Ambiente** — Verifica se Docker, Python e Git estão acessíveis
2. **Configura o Sandbox Kali** — Constrói a imagem Docker `cyber-ctf-kali` com todas as ferramentas de segurança
3. **Instala Dependências Python** — `mcp`, `fastmcp`, `pwntools`, `requests`
4. **Valida o Sistema** — Roda scripts de verificação para garantir comunicação IA ↔ Sandbox
5. **Vincula Plataformas CTF** (opcional) — CTFd, HackTheBox, TryHackMe

---

## 🐳 Arquitetura Host vs. Sandbox

O sistema mantém seu PC limpo com separação clara:

| Camada | O que roda |
|:---|:---|
| **Host (seu PC)** | Claude Code + scripts Python leves (o "cérebro") |
| **Sandbox (Docker Kali)** | `nmap`, `gdb`, `radare2`, `pwntools`, exploits (o "braço") |

### Se o Docker apresentar erros

```bash
# Verificar se está rodando
docker ps

# Linux: adicionar usuário ao grupo docker
sudo usermod -aG docker $USER && newgrp docker

# WSL2 no Windows: instalar Docker Engine no WSL
curl -fsSL https://get.docker.com | sh
```

---

## ✅ Próximo Passo

Com o ambiente configurado, você está pronto para o primeiro desafio.
👉 [**Aprenda a Usar os Comandos**](Como-Usar)
