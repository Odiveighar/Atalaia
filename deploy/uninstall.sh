#!/usr/bin/env bash
# Remove o Atalaia. Os dados em /var/lib/atalaia sao mantidos, apague manualmente se quiser.
set -euo pipefail
systemctl disable --now atalaia 2>/dev/null || true
rm -f /etc/systemd/system/atalaia.service /usr/local/bin/atalaia
rm -rf /opt/atalaia
systemctl daemon-reload
echo "Atalaia removido. Configuracao em /etc/atalaia e dados em /var/lib/atalaia foram mantidos."
