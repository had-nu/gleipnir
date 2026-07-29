#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'

cleanup() {
  echo -e "\n${Y}A encerrar...${N}"
  kill $PID_PROV 2>/dev/null || true
  kill $PID_CUBE 2>/dev/null || true
  rm -rf "$TEST_DIR"
  echo -e "${G}Parou.${N}"
}
trap cleanup EXIT INT TERM

TEST_DIR="$SCRIPT_DIR/.run"
mkdir -p "$TEST_DIR/uids"

# Pick a free port for the Gleipnir REST API
pick_port() {
  local p=$1; while lsof -ti ":$p" &>/dev/null; do p=$((p+1)); done; echo "$p"
}
REST_PORT=$(pick_port 8081)
CUBE_PORT=$(pick_port 3000)

echo -e "${C}==>${N} A compilar binários …"
go build -o bin/provenanced ./cmd/provenanced 2>&1 | tail -1
go build -o bin/provectl    ./cmd/provectl    2>&1 | tail -1
go build -o "$SCRIPT_DIR/bin/cube-room" ./frontend-test/cube-room 2>&1 | tail -1

echo -e "${C}==>${N} A gerar UID de teste …"
./bin/provectl init -n 1 -o "$TEST_DIR/uids" 2>/dev/null

echo -e "${C}==>${N} A iniciar provenanced (validador único) …"
echo -e "   REST → http://localhost:${REST_PORT}"
./bin/provenanced \
  --node-id "cubo-test" \
  --uid-file "$TEST_DIR/uids/uid-1.cbor" \
  --rest-listen ":$REST_PORT" \
  --rest-keys-dir "$TEST_DIR/uids" \
  --grpc-port "50151" &> "$TEST_DIR/provenanced.log" &
PID_PROV=$!

echo -e "   Aguardar REST API …\c"
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${REST_PORT}/v1/health" >/dev/null 2>&1; then
    echo -e " ${G}pronto${N}"
    break
  fi
  echo -n "."; sleep 1
done

echo -e "${C}==>${N} A iniciar cube-room …"
echo -e "   → http://localhost:${CUBE_PORT}"
"$SCRIPT_DIR/bin/cube-room" \
  --uid "$TEST_DIR/uids/uid-1.cbor" \
  --gleipnir "http://localhost:${REST_PORT}" \
  --listen ":$CUBE_PORT" &> "$TEST_DIR/cube-room.log" &
PID_CUBE=$!

sleep 1

echo ""
echo -e "${G}  ┌────────────────────────────────────────────────┐${N}"
echo -e "${G}  │  Cube Room pronto                             │${N}"
echo -e "${G}  │  ─────────────────                             │${N}"
echo -e "${G}  │  Frontend   →  http://localhost:${CUBE_PORT}             │${N}"
echo -e "${G}  │  Backend    →  http://localhost:${REST_PORT}/v1/          │${N}"
echo -e "${G}  │                                                │${N}"
echo -e "${G}  │  Logs:                                         │${N}"
echo -e "${G}  │    tail -f frontend-test/.run/provenanced.log  │${N}"
echo -e "${G}  │    tail -f frontend-test/.run/cube-room.log    │${N}"
echo -e "${G}  │                                                │${N}"
echo -e "${G}  │  Ctrl+C  para parar tudo                      │${N}"
echo -e "${G}  └────────────────────────────────────────────────┘${N}"
echo ""

wait
