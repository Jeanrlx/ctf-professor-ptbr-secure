# 🧠 Modelos de IA e Custos

O **CTF Professor** utiliza IAs de fronteira (Large Language Models) para analisar binários, interagir com o terminal e atuar como seu mentor socrático. Escolher o modelo certo é a diferença entre uma experiência de aprendizado incrível e horas de frustração.

Este fork roda via **Claude Code** (Anthropic), suportando os modelos **Claude Sonnet** e **Claude Opus**.

---

## 🏆 A Regra de Ouro: Use Sempre o Modelo Mais Capaz Disponível

Para 99% das tarefas de cibersegurança neste projeto, **recomendamos expressamente o uso de modelos da classe "Sonnet" ou "Opus"**.

### Por que não usar modelos menores (Haiku)?

Embora modelos menores sejam mais rápidos e baratos, eles falham em cenários críticos de segurança:

1. **Engenharia Reversa e Pwn**: Modelos menores não conseguem manter o contexto complexo de registradores, *ROP chains* ou leitura de código Assembly profundo.
2. **Alucinação de Comandos**: Modelos pequenos tendem a "inventar" flags de linha de comando que não existem (ex: `nmap --scan-all-vulns`), resultando em erros e perda de tempo.
3. **A Nuance Socrática**: O método de ensino do Professor requer muita sutileza — avaliar o que você digitou e responder com uma pergunta que guie seu raciocínio sem entregar a flag. Modelos menores estragam a surpresa ou avaliam sua resposta de forma errada.

*Use Haiku apenas para processar logs gigantes (centenas de milhares de linhas) para extração de texto bruto.*

---

## ⚙️ Como Configurar o Modelo no Claude Code

Ao iniciar o Claude Code, o modelo padrão é o **Claude Sonnet** (recomendado para CTF). Para trocar:

```bash
# Ver modelo atual
claude /model

# Trocar para Opus (máxima capacidade)
claude --model claude-opus-4-5

# Trocar para Sonnet (equilíbrio ideal)
claude --model claude-sonnet-4-5
```

Ou dentro da sessão ativa, use `/model` para alternar.

---

## 💰 Custos e Planos

| Plano | Modelos Disponíveis | Ideal Para |
|:---|:---|:---|
| **Claude Free** | Sonnet (limitado) | Estudantes iniciantes |
| **Claude Pro** (~$20/mês) | Sonnet + Opus sem limite prático | CTF regular, 2-5 desafios/dia |
| **API (Pay-as-you-go)** | Todos os modelos | Uso programático / automação |

### Estimativa por desafio CTF completo (5-8 interações densas)

- **Tokens de entrada** (prompt + histórico): ~40.000 tokens
- **Tokens de saída** (respostas): ~5.000 tokens
- **Custo Sonnet**: ~$0.18 USD por desafio (~R$ 1,00)
- **Custo Opus**: ~$0.90 USD por desafio (~R$ 5,00)

### Estratégia de Economia

O sistema cria automaticamente o arquivo `notes.md` na pasta do seu desafio. Se a conversa ficar muito longa e cara, limpe a sessão e reinicie apontando para a mesma pasta — a IA lerá o `notes.md` e continuará exatamente de onde você parou, custando muito menos tokens de contexto.

---

## 🔗 Próximos Passos
👉 [**Retornar para a Home da Wiki**](Home)
