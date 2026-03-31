#!/bin/bash
# ================================================
# Veil Protocol — Установка сервера
# Запусти на VPS:
#   curl -fsSL https://raw.githubusercontent.com/USER/veil-core/main/install/server.sh | bash
# ================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
BOLD='\033[1m'

echo ""
echo -e "${BLUE}${BOLD}  🛡️  Veil Protocol — Установка сервера${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Запусти от root: sudo bash install.sh${NC}"
  exit 1
fi

# Detect OS
if [ -f /etc/debian_version ]; then
  PKG="apt-get"
  $PKG update -qq
  $PKG install -y -qq golang-go curl > /dev/null 2>&1
elif [ -f /etc/redhat-release ]; then
  PKG="yum"
  $PKG install -y -q golang curl > /dev/null 2>&1
elif [ -f /etc/arch-release ]; then
  PKG="pacman"
  $PKG -Sy --noconfirm go curl > /dev/null 2>&1
else
  echo -e "${YELLOW}Неизвестная ОС. Установи Go 1.21+ вручную и запусти скрипт снова.${NC}"
  exit 1
fi

echo -e "${GREEN}✓${NC} Зависимости установлены"

# Install directory
INSTALL_DIR="/opt/veil"
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

# Download or build
if [ -d "veil-core" ]; then
  cd veil-core
  git pull -q
else
  git clone -q https://github.com/CYHTm/veil-core.git
  cd veil-core
fi

echo -e "${GREEN}✓${NC} Код загружен"

# Build
go build -o /usr/local/bin/veil-server ./cmd/veil-server/
go build -o /usr/local/bin/veil-client ./cmd/veil-client/
go build -o /usr/local/bin/veil-analyze ./cmd/veil-analyze/
chmod +x /usr/local/bin/veil-server /usr/local/bin/veil-client /usr/local/bin/veil-analyze

echo -e "${GREEN}✓${NC} Бинарники собраны"

# Generate secret if not exists
CONFIG_DIR="/etc/veil"
mkdir -p $CONFIG_DIR

if [ ! -f "$CONFIG_DIR/server.json" ]; then
  # Generate random secret
  SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 24)
  PORT=443

  # Detect public IP
  PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "YOUR_IP")

  cat > $CONFIG_DIR/server.json << CFGEOF
{
  "listen": ":${PORT}",
  "secret": "${SECRET}",
  "transport": "raw",
  "cipher": "chacha20-poly1305",
  "max_streams": 256
}
CFGEOF

  chmod 600 $CONFIG_DIR/server.json
  echo -e "${GREEN}✓${NC} Конфиг создан"
else
  # Read existing config
  SECRET=$(grep '"secret"' $CONFIG_DIR/server.json | cut -d'"' -f4)
  PORT=$(grep '"listen"' $CONFIG_DIR/server.json | grep -oP '\d+')
  PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_IP")
  echo -e "${YELLOW}✓${NC} Используем существующий конфиг"
fi

# Create systemd service
cat > /etc/systemd/system/veil-server.service << SVCEOF
[Unit]
Description=Veil Protocol Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/veil-server -config /etc/veil/server.json
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable veil-server
systemctl restart veil-server

echo -e "${GREEN}✓${NC} Сервис запущен"

# Firewall
if command -v ufw &> /dev/null; then
  ufw allow $PORT/tcp > /dev/null 2>&1
  ufw allow $PORT/udp > /dev/null 2>&1  # QUIC/HTTP3
  echo -e "${GREEN}✓${NC} Фаервол настроен (ufw)"
elif command -v firewall-cmd &> /dev/null; then
  firewall-cmd --permanent --add-port=$PORT/tcp > /dev/null 2>&1
  firewall-cmd --permanent --add-port=$PORT/udp > /dev/null 2>&1  # QUIC/HTTP3
  firewall-cmd --reload > /dev/null 2>&1
  echo -e "${GREEN}✓${NC} Фаервол настроен (firewalld)"
fi

# Generate client link
LINK="veil://${SECRET}@${PUBLIC_IP}:${PORT}"

echo ""
echo -e "${BLUE}${BOLD}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✅ Veil сервер установлен и запущен!${NC}"
echo -e "${BLUE}${BOLD}════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Ссылка для подключения:${NC}"
echo ""
echo -e "  ${YELLOW}${LINK}${NC}"
echo ""
echo -e "  Отправь эту ссылку клиентам."
echo -e "  Они вставят её в Veil и подключатся."
echo ""
echo -e "  ${BOLD}Управление:${NC}"
echo -e "    systemctl status veil-server   — статус"
echo -e "    systemctl restart veil-server  — перезапуск"
echo -e "    systemctl stop veil-server     — остановка"
echo -e "    journalctl -u veil-server -f   — логи"
echo ""
echo -e "  ${BOLD}Конфиг:${NC} /etc/veil/server.json"
echo -e "  ${BOLD}Бинарник:${NC} /usr/local/bin/veil-server"
echo ""
