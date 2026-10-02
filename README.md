# RAFAELA Generator

Painel privado para administrar keys `REMOTE-IOS-XXXXXX`.

## Incluído
- Login administrativo
- Geração 1d / 7d / 30d / lifetime / custom
- 1 a 100 keys por geração
- SQLite com `UNIQUE` + retry para impedir duplicadas
- Validade iniciada na primeira ativação
- Vínculo por `device_token`
- Pausar / retomar preservando tempo
- Reset device
- Ativar / desativar / excluir
- Busca e filtro
- `POST /api/client/activate`
- `GET /api/health`

## Shard
1. Extraia/suba o projeto.
2. Configure as variáveis de `.env.example` no painel da hospedagem.
3. Start command: `npm start`
4. A aplicação usa a porta fornecida por `PORT`.

Durante o desenvolvimento use o domínio grátis da Shard.
O domínio final planejado é `rafaela.xyz`.

**Não publique seu `.env`.**
