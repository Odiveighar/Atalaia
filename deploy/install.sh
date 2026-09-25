#!/usr/bin/env bash
# Instalador do Atalaia. Uso: sudo bash deploy/install.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Execute como root: sudo bash deploy/install.sh"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 nao encontrado. Instale com: apt install -y python3"
    exit 1
fi

python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || {
    echo "Atalaia precisa de Python 3.9 ou superior."
    exit 1
}

SRC="$(cd "$(dirname "$0")/.." && pwd)"

echo "Copiando arquivos para /opt/atalaia"
mkdir -p /opt/atalaia
rm -rf /opt/atalaia/atalaia
cp -r "$SRC/atalaia" /opt/atalaia/

mkdir -p /etc/atalaia /var/lib/atalaia
chmod 700 /var/lib/atalaia

if [ ! -f /etc/atalaia/config.json ]; then
    cp "$SRC/config.example.json" /etc/atalaia/config.json
    sed -i "s/\"host_name\": \"minha-vps\"/\"host_name\": \"$(hostname)\"/" /etc/atalaia/config.json
    echo "Configuracao criada em /etc/atalaia/config.json"
fi

if [ ! -f /etc/atalaia/env ]; then
    printf '# Chave da API da Anthropic para o agente de IA\nANTHROPIC_API_KEY=\n' > /etc/atalaia/env
fi
chmod 600 /etc/atalaia/env /etc/atalaia/config.json

cat > /usr/local/bin/atalaia <<'WRAP'
#!/usr/bin/env bash
set -a
[ -f /etc/atalaia/env ] && . /etc/atalaia/env
set +a
cd /opt/atalaia && exec python3 -m atalaia "$@"
WRAP
chmod 755 /usr/local/bin/atalaia

cp "$SRC/deploy/atalaia.service" /etc/systemd/system/atalaia.service
systemctl daemon-reload
systemctl enable --now atalaia

echo ""
atalaia check || true
echo ""
echo "Atalaia instalado e rodando."
echo "  Ver status:      atalaia status"
echo "  Ver alertas:     atalaia alerts"
echo "  Logs do agente:  journalctl -u atalaia -f"
echo "  Ajustar config:  nano /etc/atalaia/config.json && systemctl restart atalaia"
