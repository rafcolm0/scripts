#!/usr/bin/env bash
# Install movie-grabber as a systemd service on Ubuntu.
#   sudo ./install.sh [user-to-run-as]
# The service user must be able to read qBittorrent's download folder and write to the Plex library.
set -euo pipefail

RUN_AS="${1:-${SUDO_USER:-}}"
APP_DIR=/opt/movie-grabber
CONF_DIR=/etc/movie-grabber
ENV_FILE=/etc/movie-grabber.env
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then echo "Run with sudo." >&2; exit 1; fi
if [[ -z "$RUN_AS" ]] || ! id "$RUN_AS" >/dev/null 2>&1; then
    echo "Usage: sudo $0 <user-to-run-as>" >&2; exit 1
fi

echo "==> Installing packages"
apt-get install -y -q python3 python3-venv >/dev/null

echo "==> Installing app to $APP_DIR"
mkdir -p "$APP_DIR"
rm -rf "$APP_DIR/movie_grabber"
cp -r "$SRC_DIR/movie_grabber" "$SRC_DIR/requirements.txt" "$APP_DIR/"
[[ -d "$APP_DIR/venv" ]] || python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo "==> Config in $CONF_DIR"
mkdir -p "$CONF_DIR"
[[ -f "$CONF_DIR/config.yaml" ]] || cp "$SRC_DIR/config.example.yaml" "$CONF_DIR/config.yaml"
[[ -f "$CONF_DIR/movies.txt" ]] || cp "$SRC_DIR/movies.example.txt" "$CONF_DIR/movies.txt"
chown -R "$RUN_AS": "$CONF_DIR"
chmod 700 "$CONF_DIR"
chmod 600 "$CONF_DIR/config.yaml"

if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<'EOF'
# Secrets referenced from config.yaml as ${NAME}
QB_PASSWORD=
SMTP_PASSWORD=
PLEX_TOKEN=
# JACKETT_API_KEY=
# PROWLARR_API_KEY=
EOF
fi
chown "$RUN_AS": "$ENV_FILE"
chmod 600 "$ENV_FILE"

echo "==> Command wrapper /usr/local/bin/movie-grabber"
cat > /usr/local/bin/movie-grabber <<EOF
#!/usr/bin/env bash
set -a; [[ -r $ENV_FILE ]] && . $ENV_FILE; set +a
exec $APP_DIR/venv/bin/python -m movie_grabber -c $CONF_DIR/config.yaml "\$@"
EOF
chmod 755 /usr/local/bin/movie-grabber

echo "==> systemd unit"
cp "$SRC_DIR/systemd/movie-grabber@.service" /etc/systemd/system/
systemctl daemon-reload

cat <<EOF

Installed. Next steps:
  1. Edit $CONF_DIR/config.yaml  (library folders, qBittorrent URL, email)
  2. Put secrets in $ENV_FILE     (QB_PASSWORD, SMTP_PASSWORD, ...)
  3. Edit $CONF_DIR/movies.txt    (your wanted list)
  4. Test:   sudo -u $RUN_AS movie-grabber test
             sudo -u $RUN_AS movie-grabber search "The Matrix (1999)"
  5. Start:  sudo systemctl enable --now movie-grabber@$RUN_AS
     Logs:   journalctl -u movie-grabber@$RUN_AS -f
EOF
