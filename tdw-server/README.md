# Development

```sh
curl -fsSL https://bun.sh/install | bash 
bun install
docker compose up
bunx prisma generate
DATABASE_URL=postgresql://tsp-test@127.0.0.1:5432/tsp-test bunx prisma db push
DOMAIN=tdw.tsp-test.org DATABASE_URL=postgresql://tsp-test@127.0.0.1:5432/tsp-test bun serve
```
