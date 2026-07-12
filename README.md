# Codex Telegram Unificado

Versão autocontida do cliente Codex e do bot Telegram. Todo o código Python fica em
`codex_telegram_unificado.py`; ele não importa `codex_client.py` nem outro módulo local.

## Correções incluídas

- remove imports locais e símbolos ausentes que encerravam o container;
- procura `auth*.json` dinamicamente, inclusive logo após uma importação;
- envia URL e código do device code ao Telegram antes de iniciar o polling;
- mantém o polling do device code em segundo plano por até 15 minutos;
- diferencia device code desabilitado de autorização ainda pendente;
- gera e valida `state` no login PKCE;
- aceita a URL de callback diretamente ou via `/callback`;
- adiciona botão e comando para importar `.json`;
- valida tamanho, UTF-8, estrutura e tokens do JSON antes de gravar;
- grava contas de forma atômica em `DATA_DIR/authN.json` com permissão restrita;
- recarrega e seleciona a conta importada sem reiniciar o bot;
- corrige o encaminhamento da resposta de tamanho personalizado;
- valida dimensões personalizadas e limita o total de pixels;
- divide respostas longas para respeitar o limite do Telegram;
- protege renovação de token contra concorrência;
- redige tokens de mensagens de erro e reduz logs HTTP;
- executa como usuário sem privilégios no container.

## Variáveis de runtime

No Coolify, configure as variáveis abaixo com **Available at Runtime**. Deixe
**Available at Buildtime desmarcado**, especialmente para `TELEGRAM_BOT_TOKEN`.

| Variável | Obrigatória | Padrão |
|---|---:|---|
| `TELEGRAM_BOT_TOKEN` | sim | nenhum |
| `DATA_DIR` | não | `/app/data` no Docker |
| `DEFAULT_MODEL` | não | `gpt-5.4-mini` |
| `IMAGE_MODEL` | não | `gpt-image-2` |
| `MAX_IMAGES` | não | `5`, limitado a 5 |
| `ALLOWED_TELEGRAM_USER_IDS` | recomendada | vazio, permite todos |
| `LOG_LEVEL` | não | `INFO` |

O token que apareceu nos logs anteriores deve ser revogado no BotFather. Use um token
novo; retirar a opção de buildtime não torna o token antigo seguro novamente.

## Configuração exata no Coolify

1. Crie um recurso do tipo **Application** usando o repositório
   `https://github.com/sonyddr666/codex-image-telegram` e a branch `main`.
2. Selecione **Dockerfile** como build pack. O Dockerfile fica em `/Dockerfile` e o
   diretório base é `/`.
3. Este bot usa polling do Telegram: ele **não expõe porta HTTP**, não precisa de domínio e
   não precisa de health check por URL. Remova qualquer domínio/porta gerado automaticamente.
4. Em **Environment Variables**, adicione `TELEGRAM_BOT_TOKEN` com o token novo. Marque
   somente **Available at Runtime**; deixe **Available at Buildtime** desmarcado.
5. Adicione `ALLOWED_TELEGRAM_USER_IDS` com seu ID numérico do Telegram. Separe vários IDs
   por vírgula.
6. Em **Persistent Storage**, crie um volume e monte-o em `/app/data`. Sem esse volume, as
   contas importadas e as imagens desaparecem quando o container for recriado.
7. Salve as configurações e faça **Deploy**. Nos logs da aplicação deve aparecer
   `Iniciando codex-telegram-unificado`, sem `Traceback` e sem o token.

Configuração recomendada das variáveis:

```text
TELEGRAM_BOT_TOKEN       Buildtime: não | Runtime: sim
DATA_DIR=/app/data       Buildtime: não | Runtime: sim
DEFAULT_MODEL            Buildtime: não | Runtime: sim
IMAGE_MODEL              Buildtime: não | Runtime: sim
MAX_IMAGES               Buildtime: não | Runtime: sim
ALLOWED_TELEGRAM_USER_IDS Buildtime: não | Runtime: sim
```

Se preferir criar um recurso **Docker Compose**, use o `docker-compose.yml` da raiz. Não
configure simultaneamente o modo Dockerfile e o modo Compose para a mesma aplicação.

## Deploy com Docker Compose

1. Copie `.env.example` para `.env` apenas no servidor/local e preencha o token novo.
2. Defina `ALLOWED_TELEGRAM_USER_IDS` com seu ID numérico para impedir acesso público.
3. Execute:

```bash
docker compose up -d --build
docker compose logs -f --tail 200
```

No Coolify, use esta pasta como raiz da aplicação e mantenha um volume persistente em
`/app/data`. Contas, referências e imagens ficam dentro desse volume.

## Login

Envie `/login` e escolha uma opção:

### Device Code

O bot solicita o código, envia a URL e o código ao Telegram e acompanha a aprovação em
segundo plano. Algumas contas exigem habilitar device code nas configurações de segurança
do ChatGPT; workspaces gerenciados podem depender da permissão do administrador. Use
`/cancelar` para interromper.

### Navegador (PKCE)

O bot envia um botão de login. Ao final, o navegador tenta abrir
`http://localhost:1455/auth/callback` e pode exibir erro de conexão. Copie a URL completa da
barra de endereço e envie ao bot. O callback só é aceito quando o `state` corresponde ao
login iniciado naquela sessão.

### Importar JSON

Toque em **Importar arquivo .json** ou envie `/importar`, depois envie o documento. Formatos
aceitos:

- `auth.json` do Codex CLI, com objeto `tokens`;
- `credential_pool.openai-codex`;
- objeto direto com `access_token`;
- lista contendo contas nesses formatos.

O nome recebido não é usado como caminho. Cada conta é normalizada para `authN.json`; uma
conta já existente é atualizada quando estiver em arquivo individual.

`auth.json` contém credenciais equivalentes a uma senha. Não o envie para bots de terceiros,
não o coloque no Git e não o exponha em logs.

## Comandos do Telegram

| Comando | Função |
|---|---|
| `/start` | ajuda e conta selecionada |
| `/login` | device code, PKCE ou importação |
| `/importar` | aguarda um documento JSON |
| `/callback <url>` | conclui PKCE |
| `/cancelar` | cancela login ou imagem pendente |
| `/contas` | lista contas persistidas |
| `/usar <n>` | seleciona uma conta manualmente |
| `/status` | mostra quota restante e reset |
| `/limpar` | limpa o histórico de chat em memória |
| `/imagem <prompt>` | gera uma imagem |
| `/imagem <n> <prompt>` | gera até cinco imagens |

Envie uma foto para iniciar edição. O bot pede prompt, tamanho, qualidade e fundo.

## Validação local

```bash
python -m py_compile codex_telegram_unificado.py
python -c "import codex_telegram_unificado; print('import ok')"
docker compose config
```

O cliente preserva os endpoints utilizados pelo projeto original para chat, quota e imagem.
Esses endpoints de backend podem mudar; para integrações novas e estáveis, acompanhe a
documentação oficial do Codex App Server e da API OpenAI.

## Solução de problemas

- **Exited / Restarting:** abra os logs da aplicação, não apenas Deployment Logs. Procure a
  última linha do traceback.
- **Device code indisponível:** habilite device code na segurança da conta ChatGPT ou peça ao
  administrador do workspace. Como alternativa, use PKCE ou importe `auth.json`.
- **Unauthorized / token inválido no Telegram:** gere um token novo no BotFather e atualize a
  variável de runtime.
- **Conflict: terminated by other getUpdates request:** há outra instância usando o mesmo bot.
  Deixe apenas um container/processo ativo.
- **Contas somem após deploy:** confirme o volume persistente montado exatamente em
  `/app/data`.
- **Imagem retorna 403:** a conta selecionada não possui acesso ao recurso de imagens.
- **Build mostra `ARG TELEGRAM_BOT_TOKEN`:** a variável ainda está marcada como Buildtime no
  Coolify. Desmarque, salve e faça novo deploy.
