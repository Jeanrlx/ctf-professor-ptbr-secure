# 🧰 Ferramentas Locais Essenciais (Host)

Para resolver desafios de CTF com eficiência, você precisará de ferramentas no seu computador (Host) para abrir, analisar e manipular arquivos rapidamente. Embora IDEs pesadas como o VS Code sejam úteis para desenvolvimento, elas costumam "engasgar" com arquivos de log gigantes ou não possuem as ferramentas de baixo nível nativas para análise binária.

Aqui está o "Padrão Ouro" recomendado pelo **CTF Professor** para o seu kit de sobrevivência local:

---

## 1. Notepad++ (O Canivete Suíço de Texto)

O **Notepad++** é obrigatório no Windows. Ele é extremamente leve e consegue abrir wordlists e arquivos `.pcap` exportados com gigabytes de tamanho em segundos, sem travar o seu PC.

### 🔌 Plugins Essenciais para CTF
Para transformar o Notepad++ em uma ferramenta hacker, instale os seguintes plugins (Vá em `Plugins > Plugins Admin...`):

*   **MIME Tools** *(Nativo)*: Selecione qualquer texto e vá em `Plugins > MIME Tools` para codificar/decodificar **Base64** instantaneamente.
*   **Converter** *(Nativo)*: Converte texto de/para Hexadecimal e ASCII de forma rápida.
*   **HEX-Editor**: Fundamental! Adiciona um botão com um "H" na barra de ferramentas. Clicando nele, você visualiza o código hexadecimal de qualquer arquivo (útil para analisar binários corrompidos ou procurar *magic bytes*).
*   **JSON Viewer**: Se você pegar um dump de API de um desafio Web, esse plugin formata o JSON e cria uma árvore lateral para navegação fácil.
*   **NppCrypt**: Permite criptografar e descriptografar textos selecionados rapidamente com dezenas de algoritmos.

> **Dica Claude Code**: Se você usa o Notepad++, pode configurá-lo como editor padrão para abertura de arquivos. No PowerShell (como Administrador), rode: `[Environment]::SetEnvironmentVariable("EDITOR", "C:\Program Files\Notepad++\notepad++.exe", "User")`.

---

## 2. CyberChef (A Cozinha de Dados)

O **CyberChef** (criado pelo GCHQ) é a melhor ferramenta do mundo para manipulação de dados em CTFs.

*   **O que faz**: Ele permite encadear "receitas" de operações. Exemplo: Pegar um texto -> Decodificar de Base64 -> Fazer um XOR com a chave "A" -> Extrair os endereços IP resultantes.
*   **Como ter**: Recomendamos **baixar a versão HTML local** [direto do repositório oficial](https://github.com/gchq/CyberChef/releases) para que você não precise enviar dados sensíveis (ou malware) de CTFs para a internet. Basta abrir o arquivo `.html` no seu navegador.

---

## 3. Editor Hexadecimal Dedicado (ImHex / HxD)

Embora o plugin do Notepad++ quebre um galho, desafios de **Forense** e **Engenharia Reversa (Pwn)** exigem editores profissionais.

*   **ImHex**: Um editor hexadecimal moderno, multiplataforma, desenhado especificamente para engenharia reversa. Possui mapeamento visual de estruturas e *parsers* integrados. É visualmente deslumbrante e incrivelmente útil.
*   **HxD**: A opção clássica e ultra-rápida exclusiva para Windows. Pode abrir discos rígidos inteiros e ler a memória RAM diretamente.

---

## 🔄 Como o Agente sabe o que eu tenho?

Durante o processo do comando `/install`, o sistema perguntará quais dessas ferramentas você possui e salvará essa informação no arquivo `.env`. 

Dessa forma, o **CTF Professor** saberá se pode sugerir para você "abra isso no Notepad++ e use o plugin X" ou "crie uma receita no CyberChef", tornando as dicas muito mais personalizadas ao seu ambiente!
