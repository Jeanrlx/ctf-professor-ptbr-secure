---
description: Configura o ambiente local, constrói o sandbox Docker e instala dependências necessárias. Execute isso após clonar o repositório.
---

# /install — Configurar o Ambiente do Professor CTF

$ARGUMENTS

---

## Tarefa

### Passo 1: Sonda de Ambiente (SO & Dependências)

1. **Invoque** a skill `security-toolchain-manager` para sondar o sistema.
2. **Verifique os requisitos principais:**
   - Docker (Necessário para o sandbox)
   - Python 3.8+ (Necessário para scripts)
   - Git (Necessário para controle de versão)
3. **Detecção de idioma:** Detecte o idioma do usuário (EN ou PT-BR) e responda de acordo.

### Passo 2: Inicialização do Sandbox Docker

1. **Verifique** se a imagem `cyber-ctf-kali` existe.
2. **Se estiver faltando:** Construa a imagem usando `.agent/sandbox/Dockerfile`.
   - Comando: `docker build -t cyber-ctf-kali .agent/sandbox/`
3. **Verifique** a integridade da imagem e a presença de ferramentas dentro do contêiner.

### Passo 3: Configuração de Dependências Python

1. **Verifique** se faltam bibliotecas Python usadas pelo sistema local (host):
   - `mcp` / `fastmcp` (para o servidor do sandbox)
2. **Ofereça** para instalar dependências ausentes:
   - Comando: `pip install mcp fastmcp`
   - *Nota:* Ferramentas de exploração (como `pwntools`, `requests`, etc.) NÃO devem ser instaladas no host. Elas são exclusivas do contêiner Kali Linux.

### Passo 4: Verificação do Sistema

1. **Execute** o script `.agent/scripts/verify_all.py` (se aplicável) ou um subconjunto dele para garantir que o ambiente esteja pronto.
2. **Teste** o `sandbox_manager.py` iniciando e parando o contêiner.

### Passo 5: Configuração Final

1. **Verifique** se `mcp_config.json` precisa de atualizações de caminho local.

### Passo 6: Ferramentas Locais (Host)

1. **Verifique** editores de texto e hexadecimais locais essenciais (Notepad++, ImHex/HxD, CyberChef).
2. **Sugira Instalação:** Se o usuário não os tiver, o script fornecerá links de download ou comandos `winget`.
3. **Salve o Estado:** Registre as ferramentas instaladas no `.env` para que os agentes possam fornecer dicas contextuais.

### Passo 7: Conexão com Plataformas de CTF (Opcional)

1. **Vincule** suas contas de CTF para permitir a ingestão automatizada de desafios e submissão de flags.
2. **Selecione a Plataforma:**
   - **CTFd**: Requer URL da Plataforma e Token de Acesso.
   - **HackTheBox**: Requer Token de Aplicativo (v4).
   - **TryHackMe**: Requer Cookie de Sessão (`connect.sid`).
3. **Orientação:** O agente fornecerá instruções passo a passo sobre onde encontrar esses tokens para cada plataforma.
4. **Armazenamento:** As credenciais são salvas de forma segura em um arquivo `.env` local (ignorado pelo Git).

### Passo 8: Conclusão

1. **Confirme** que o usuário está pronto para iniciar sua primeira sessão de CTF com `/start-ctf`.

---

## Exemplos de Uso

```
/install
/install --skip-docker
/install --force-rebuild
```

---

## Regras

- **Transparência:** Sempre explique o que um comando faz antes de executá-lo (especialmente `docker build` e `pip install`).
- **Segurança:** Não force instalações sem o consentimento do usuário.
- **Bilíngue:** Forneça todas as mensagens de status e prompts no idioma detectado.
