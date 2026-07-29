# Cube Room — teste de integração local

```bash
./frontend-test/start.sh
# Abre http://localhost:3000
# Ctrl+C para parar
```

Requisitos: Go 1.25+, portas 3000 e 8080 livres.

O script compila os binários, gera UID de teste, inicia o
`provenanced` como validador único e o `cube-room` como
frontend do ritual de vinculação.
