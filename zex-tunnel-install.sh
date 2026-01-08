#!/usr/bin/env bash
set -euo pipefail

# =========================================================
#                ZEX Tunnel V3 — Installer (beta)
# =========================================================

VERSION="V3.250908"
BASE_DIR="/root/ZEX-Tunnel"
CFG_DIR="$BASE_DIR/config"              # Source config directory (READ-ONLY; never modified)
PANEL_PATH="/usr/local/bin/zt"
INSTALL_SCRIPT="$BASE_DIR/zex-tunnel-install.sh"   # Save this script at this path for panel option 10

# -------------------- Logging (alongside script) --------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/install-$(date +'%Y%m%d-%H%M%S').log"

# If script directory is not writable, fall back to /tmp
if ! ( : >"$LOG_FILE" ) 2>/dev/null; then
  LOG_FILE="/tmp/zex-tunnel-install-$(date +'%Y%m%d-%H%M%S').log"
  : >"$LOG_FILE"
fi

exec > >(tee -a "$LOG_FILE") 2>&1

echo "===================================================="
echo "ZEX Tunnel installer started at: $(date -Is)"
echo "Version: $VERSION"
echo "Script: ${BASH_SOURCE[0]}"
echo "Log file: $LOG_FILE"
echo "User: $(id -u)  Host: $(hostname)"
echo "===================================================="

trap 'rc=$?;
  echo "!! ERROR: exit_code=$rc at line=$LINENO command: $BASH_COMMAND";
  echo "Log file: $LOG_FILE";
  exit $rc' ERR

# Enable by: TRACE=1 bash script.sh
if [[ "${TRACE:-0}" == "1" ]]; then
  set -x
  export PS4="+ [${BASH_SOURCE##*/}:${LINENO}] "
fi
# -------------------- End Logging --------------------

# Services
SERVICE_TUN="zextunnel"
SERVICE_WEB="zexweb"

# Binaries (expected paths)
BIN_TUN="$BASE_DIR/Waterwall"
BIN_WEB="$BASE_DIR/web.py"

# Files in MAIN (mutable)
CORE_MAIN="$BASE_DIR/core.json"
CONF_IR_MAIN="$BASE_DIR/config_ir.json"
CONF_KH_MAIN="$BASE_DIR/config_kharej.json"
CONF_ZEX_MAIN="$BASE_DIR/config.zex"     # 4 lines: IRAN_IP, KHAREJ_IP, PROTOCOL, PORTS (space-separated or empty for Kharej)
WEB_ZEX_MAIN="$BASE_DIR/web.zex"         # optional 4 lines: port, reserved, pass, reserved

# Files in CONFIG (immutable; we ONLY copy these)
CORE_SRC="$CFG_DIR/core.json"
CONF_IR_SRC="$CFG_DIR/config_ir.json"
CONF_KH_SRC="$CFG_DIR/config_kharej.json"

# -------------------- UI helpers --------------------
CLR(){ printf "\e[%sm%b\e[0m" "$1" "$2"; }
BANNER(){
  clear
  CLR "36;1" "====================================================\n"
  CLR "37;1" "                 ZEX Tunnel V3 Setup\n"
  CLR "36;1" "====================================================\n\n"
}

# -------------------- Guards --------------------
if [[ $EUID -ne 0 ]]; then
  echo "This installer must be run as root. Please use: sudo bash $0"
  exit 1
fi

if [[ -r /etc/os-release ]]; then
  UBUNTU_VERSION=$(grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
else
  UBUNTU_VERSION=""
fi
case "$UBUNTU_VERSION" in
  20.04|22.04|20.*|22.*) : ;;
  *) echo "Unsupported Ubuntu $UBUNTU_VERSION (supported: 20.04–20.x, 22.04–22.x)"; exit 1;;
esac

# -------------------- FS helpers --------------------
require_file() { local f="$1"; [[ -f "$f" ]] || { echo "Missing required file: $f"; exit 1; }; }
ensure_layout(){ mkdir -p "$BASE_DIR" "$CFG_DIR"; }

# -------------------- Deps --------------------
install_deps() {
  echo
  echo "Installing dependencies..."
  apt update -y
  apt install -y python3 python3-pip unzip wget curl jq
  pip3 install -U flask flask-socketio eventlet psutil
}

# -------------------- Validation --------------------
validate_domain_ip() {
  local s="$1"
  [[ -n "$s" ]] || return 1
  [[ "$s" =~ ^[A-Za-z0-9._:-]+$ ]] || return 1
  [[ ${#s} -le 253 ]] || return 1
  return 0
}
validate_protocol() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p>=0 && p<=255 )) || return 1
  return 0
}
validate_ports() {
  local ports_str="$1"
  [[ -n "$ports_str" ]] || return 1
  local -A seen=()
  local p count=0
  for p in $ports_str; do
    ((count++))
    if (( count > 10 )); then
      echo "Too many ports. Maximum allowed is 10." >&2
      return 1
    fi
    [[ "$p" =~ ^[0-9]+$ ]] || return 1
    (( p>=1 && p<=65535 )) || return 1
    [[ -z "${seen[$p]:-}" ]] || return 1
    seen[$p]=1
  done
  return 0
}

# -------------------- Read helpers --------------------
read_nonempty() {
  local prompt="$1" var
  while true; do
    read -r -p "$prompt" var || exit 1
    [[ -n "$var" ]] && { echo "$var"; return 0; }
    echo "Value cannot be empty."
  done
}
press_enter(){ read -r -p "Press Enter to continue... " _; }

# -------------------- Local IPs --------------------
get_local_ipv4(){
  ip -4 addr show scope global up 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1
}
get_local_ipv6(){
  ip -6 addr show scope global up 2>/dev/null | awk '/inet6/{print $2}' | cut -d/ -f1 | grep -v '^fe80:' | head -n1
}

# -------------------- JSON manipulations (via jq) --------------------
add_extra_ports_to_ir_json() {
  local json_file="$CONF_IR_MAIN"
  local ports_str="$1"
  local first=true
  local extras=() p
  for p in $ports_str; do
    if $first; then first=false; continue; fi
    extras+=("$p")
  done
  [[ ${#extras[@]} -eq 0 ]] && return 0

  local ports_json
  ports_json=$(printf '%s\n' "${extras[@]}" | jq -R . | jq -s .)

  local jq_prog='
    def mk_input(n; port):
      {name: ("input"+(n|tostring)), type:"TcpListener",
       settings:{address:"0.0.0.0", port:(port|tonumber), nodelay:true},
       next: ("output"+(n|tostring))};
    def mk_output(n; port):
      {name: ("output"+(n|tostring)), type:"TcpConnector",
       settings:{nodelay:true, address:"10.10.0.2", port:(port|tonumber)}};

    ([ .nodes[]? | select(.name|startswith("input")) ] | length) as $base
    | reduce ( $ports | to_entries[] ) as $e
        ( .;
          .nodes += [
            mk_input(($base + $e.index + 1); $e.value),
            mk_output(($base + $e.index + 1); $e.value)
          ]
        )'

  local tmpf; tmpf="$(mktemp)"
  jq --argjson ports "$ports_json" "$jq_prog" "$json_file" > "$tmpf"
  mv "$tmpf" "$json_file"
}

# Replace placeholders in MAIN copies
apply_placeholders_ir() {
  local iran_ip="$1" kh_ip="$2" proto="$3" first_port="$4"
  sed -i -e "s#__IP_IRAN__#${iran_ip}#g" \
         -e "s#__IP_KHAREJ__#${kh_ip}#g" \
         -e "s#__PROTOCOL__#${proto}#g" \
         -e "s#__PORT__#${first_port}#g" "$CONF_IR_MAIN"
}
apply_placeholders_kh() {
  local iran_ip="$1" kh_ip="$2" proto="$3"
  sed -i -e "s#__IP_IRAN__#${iran_ip}#g" \
         -e "s#__IP_KHAREJ__#${kh_ip}#g" \
         -e "s#__PROTOCOL__#${proto}#g" "$CONF_KH_MAIN"
}

# -------------------- systemd units --------------------
write_units() {
  cat >/etc/systemd/system/${SERVICE_TUN}.service <<EOF
[Unit]
Description=ZEX Tunnel (Waterwall)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$BASE_DIR
ExecStart=$BIN_TUN
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/${SERVICE_WEB}.service <<EOF
[Unit]
Description=ZEX Tunnel Web
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$BASE_DIR
ExecStart=/usr/bin/python3 $BIN_WEB
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable ${SERVICE_TUN} ${SERVICE_WEB} >/dev/null 2>&1 || true
}

# -------------------- Panel (zt) --------------------
write_panel() {
  cat >"$PANEL_PATH" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

VERSION="V3.250908"
BASE_DIR="/root/ZEX-Tunnel"
PANEL_NAME="ZEX Tunnel V3 — Panel"

SERVICE_TUN="zextunnel"
SERVICE_WEB="zexweb"

CONFIG_FILE="$BASE_DIR/config.zex"    # IRAN_IP, KHAREJ_IP, PROTOCOL, PORTS
WEB_CONFIG="$BASE_DIR/web.zex"        # port, -, pass, -
CORE_MAIN="$BASE_DIR/core.json"

CLR(){ printf "\e[%sm%b\e[0m" "$1" "$2"; }
LINE(){ printf "%s\n" "---------------------------------------------------------------------"; }
HDR(){
  clear
  CLR "36;1" "=====================================================================\n"
  CLR "37;1" "                        ${PANEL_NAME}\n"
  CLR "36;1" "=====================================================================\n\n"
}

get_location() {
  if [[ -f "$CORE_MAIN" ]]; then
    local cfg
    cfg=$(jq -r '.configs[0]' "$CORE_MAIN" 2>/dev/null || echo "")
    if [[ "$cfg" == "config_ir.json" ]]; then
      echo "Iran"; return
    elif [[ "$cfg" == "config_kharej.json" ]]; then
      echo "Kharej"; return
    fi
  fi
  echo "Unknown"
}

main_loop() {
  while true; do
    HDR
    local IRAN_IP="N/A" KHAREJ_IP="N/A" PROT="N/A" PORTS="N/A"
    if [[ -f "$CONFIG_FILE" ]]; then
      mapfile -t cfg < "$CONFIG_FILE" || true
      IRAN_IP="${cfg[0]:-N/A}"
      KHAREJ_IP="${cfg[1]:-N/A}"
      PROT="${cfg[2]:-N/A}"
      PORTS="${cfg[3]:-N/A}"
    fi

    local LOC; LOC=$(get_location)
    systemctl is-active --quiet "${SERVICE_TUN}" && ST_TUN=$(CLR 32 "ACTIVE") || ST_TUN=$(CLR 31 "INACTIVE")
    systemctl is-active --quiet "${SERVICE_WEB}" && ST_WEB=$(CLR 32 "ACTIVE") || ST_WEB=$(CLR 31 "INACTIVE")

    printf "  Server Information\n"
    LINE
    printf "   Location          : %s\n" "$LOC"
    printf "   IRAN IP/Domain    : %s\n" "$IRAN_IP"
    printf "   Kharej IP/Domain  : %s\n" "$KHAREJ_IP"
    printf "   Protocol Number   : %s\n" "$PROT"
    printf "   Tunnel Ports      : %s\n" "$PORTS"
    printf "   Active Config     : %s\n\n" "$( [[ -f "$CORE_MAIN" ]] && jq -r '.configs[0]' "$CORE_MAIN" || echo "N/A" )"

    printf "  Service Status\n"
    LINE
    printf "   %s (Main)  : %b    | Exec: %s\n" "$SERVICE_TUN" "$ST_TUN" "$BASE_DIR/Waterwall"
    printf "   %s (Web)   : %b    | Exec: %s\n\n" "$SERVICE_WEB" "$ST_WEB" "/usr/bin/python3 $BASE_DIR/web.py"

    printf "  Web API\n"
    LINE
    local WEB_PORT="N/A" WEB_PASS="N/A"
    if [[ -f "$WEB_CONFIG" ]]; then
      mapfile -t wcfg < "$WEB_CONFIG" || true
      WEB_PORT="${wcfg[0]:-N/A}"
      WEB_PASS="${wcfg[2]:-N/A}"
    fi
    printf "   Port              : %s\n" "$WEB_PORT"
    printf "   Login Password    : %s\n" "$WEB_PASS"
    printf "   Config File       : %s\n\n" "$WEB_CONFIG"

    CLR "36;1" "=====================================================================\n"
    printf "  Actions\n"
    CLR "36;1" "=====================================================================\n\n"

    printf "  Tunnel Controls\n"
    LINE
    printf "   1) Start %s\n" "$SERVICE_TUN"
    printf "   2) Stop  %s\n" "$SERVICE_TUN"
    printf "   3) Restart %s\n" "$SERVICE_TUN"
    printf "   4) View %s logs\n" "$SERVICE_TUN"
    printf "   5) Kill all Waterwall processes\n\n"

    printf "  Web Controls\n"
    LINE
    printf "   6) Start %s\n" "$SERVICE_WEB"
    printf "   7) Stop  %s\n" "$SERVICE_WEB"
    printf "   8) Restart %s\n" "$SERVICE_WEB"
    printf "   9) View %s logs\n\n" "$SERVICE_WEB"

    printf "  Configuration\n"
    LINE
    printf "   10) Reconfigure Tunnel\n"
    printf "   11) Edit Web Config\n\n"

    printf "  System / Maintenance\n"
    LINE
    printf "   15) Reload Panel Info\n"
    printf "   16) Uninstall Everything\n"
    printf "   17) Install Sanaei Xray Panel\n"
    printf "   18) Reboot Server\n\n"

    LINE
    printf "  Shortcuts: [Enter] Refresh   [Q] Quit\n"
    LINE
    printf "  If you experience tunnel connection issues, please reboot the server.\n"
    LINE
    printf "\nSelect an option (e.g., 3 or 9) > "
    read -r opt || exit 0

    case "$opt" in
      1) systemctl start "$SERVICE_TUN" ;;
      2) systemctl stop "$SERVICE_TUN" ;;
      3) systemctl restart "$SERVICE_TUN" ;;
      4) journalctl -u "$SERVICE_TUN" -n 200 --no-pager | ${PAGER:-less} ;;
      5) pkill -f "$BASE_DIR/Waterwall" || true ;;
      6) systemctl start "$SERVICE_WEB" ;;
      7) systemctl stop  "$SERVICE_WEB" ;;
      8) systemctl restart "$SERVICE_WEB" ;;
      9) journalctl -u "$SERVICE_WEB" -n 200 --no-pager | ${PAGER:-less} ;;
      10) sudo bash "$BASE_DIR/zex-tunnel-install.sh" --reconfigure; read -r -p "Press Enter..." _ ;;
      11)
         read -r -p "New Web Port: " nport
         read -r -p "New Web Password: " npass
         if [[ -f "$WEB_CONFIG" ]]; then
           mapfile -t arr < "$WEB_CONFIG"
           arr[0]="$nport"
           arr[2]="$npass"
           printf '%s\n%s\n%s\n%s\n' "${arr[0]}" "${arr[1]:-}" "${arr[2]}" "${arr[3]:-}" > "$WEB_CONFIG"
           echo "Web config updated."
           systemctl restart "$SERVICE_WEB"
         else
           echo "web.zex not found."
         fi
         read -r -p "Press Enter..." _ ;;
      15) continue ;;
      16)
         echo "You are about to uninstall ZEX Tunnel V3 and remove all services/files."
         read -r -p "Step 1 — Confirm (Y/N): " ans
         [[ "${ans,,}" == "y" ]] || { echo "Cancelled."; read -r -p "Enter..." _; continue; }
         read -r -p "Step 2 — Type 'UNINSTALL' to proceed: " tok
         [[ "$tok" == "UNINSTALL" ]] || { echo "Token mismatch. Cancelled."; read -r -p "Enter..." _; continue; }

         systemctl disable --now zextunnel zexweb || true
         rm -f /etc/systemd/system/zextunnel.service /etc/systemd/system/zexweb.service || true
         systemctl daemon-reload
         rm -rf "$BASE_DIR"
         rm -f /usr/local/bin/zt
         echo "Uninstall complete. A reboot is recommended."
         exit 0
         ;;
      17) bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh) ; exit 0 ;;
      18) echo "Rebooting..." ; sleep 1 ; reboot ;;
      q|Q|0) exit 0 ;;
      "") : ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  done
}

main_loop
EOS
  chmod +x "$PANEL_PATH"
}

# -------------------- Setup Wizard --------------------
run_wizard() {
  BANNER

  local IPV4 IPV6
  IPV4="$(get_local_ipv4)"; [[ -z "${IPV4:-}" ]] && IPV4="N/A"
  IPV6="$(get_local_ipv6)"; [[ -z "${IPV6:-}" ]] && IPV6="N/A"
  echo "IP V4: $IPV4"
  echo "IP V6: $IPV6"
  echo "---------------------------------------"
  echo "Mode: choose server location"
  echo "  [1] Iran"
  echo "  [2] Kharej"
  echo
  read -r -p "> " LOCATION_CHOICE
  case "$LOCATION_CHOICE" in
    1|2) : ;;
    *) echo "Invalid selection."; exit 1;;
  esac

  echo
  IRAN_IP=$(read_nonempty "IRAN IP/Domain: ")
  validate_domain_ip "$IRAN_IP" || { echo "Invalid IRAN IP/Domain."; exit 1; }

  KHAREJ_IP=$(read_nonempty "Kharej IP/Domain: ")
  validate_domain_ip "$KHAREJ_IP" || { echo "Invalid Kharej IP/Domain."; exit 1; }

  echo
  if [[ "$LOCATION_CHOICE" == "1" ]]; then
    echo "Protocol Number (Default 18)"
    echo "Tip: Using a protocol number below 100 is recommended."
  else
    echo "Protocol Number (Default 18)"
    echo "Note: Enter the same protocol number used on the Iran server."
    echo "Tip: Using a protocol number below 100 is recommended."
  fi
  read -r -p "> " PROTOCOL
  [[ -z "${PROTOCOL:-}" ]] && PROTOCOL=18
  validate_protocol "$PROTOCOL" || { echo "Invalid protocol number (0-255)."; exit 1; }

  PORTS=""
  if [[ "$LOCATION_CHOICE" == "1" ]]; then
    echo
    echo "Port Number(s)"
    echo "- Single-port: enter one port (e.g., 443)"
    echo "- Multi-port : enter space-separated ports (e.g., 443 2083 2087)"
    read -r -p "> " PORTS
    [[ -z "${PORTS:-}" ]] && PORTS="443"
    validate_ports "$PORTS" || { echo "Invalid port list (1-10 ports, unique, 1-65535)."; exit 1; }
  fi

  echo
  echo "----------------------------------------------------"
  echo "Review & Confirm"
  echo "  IRAN IP/Domain   : $IRAN_IP"
  echo "  Kharej IP/Domain : $KHAREJ_IP"
  echo "  Protocol Number  : $PROTOCOL"
  if [[ "$LOCATION_CHOICE" == "1" ]]; then
    echo "  Port Number(s)   : $PORTS"
  else
    echo "  Port Number(s)   : (N/A in Kharej mode)"
  fi
  echo "----------------------------------------------------"
  read -r -p "Proceed? (Y/n): " go
  [[ -z "${go:-}" || "${go,,}" == "y" ]] || { echo "Cancelled."; exit 1; }

  printf '%s\n%s\n%s\n%s\n' "$IRAN_IP" "$KHAREJ_IP" "$PROTOCOL" "${PORTS:-}" > "$CONF_ZEX_MAIN"

  if [[ "$LOCATION_CHOICE" == "1" ]]; then
    cp -f "$CORE_SRC" "$CORE_MAIN"
    sed -i -e 's#"__CONFIG_FILE__"#"config_ir.json"#g' "$CORE_MAIN"
    cp -f "$CONF_IR_SRC" "$CONF_IR_MAIN"
    first_port="${PORTS%% *}"
    apply_placeholders_ir "$IRAN_IP" "$KHAREJ_IP" "$PROTOCOL" "$first_port"
    add_extra_ports_to_ir_json "$PORTS"
  else
    cp -f "$CORE_SRC" "$CORE_MAIN"
    sed -i -e 's#"__CONFIG_FILE__"#"config_kharej.json"#g' "$CORE_MAIN"
    cp -f "$CONF_KH_SRC" "$CONF_KH_MAIN"
    apply_placeholders_kh "$IRAN_IP" "$KHAREJ_IP" "$PROTOCOL"
  fi
}

# -------------------- Reconfigure flow --------------------
reconfigure_flow() {
  echo "Temporarily disabling services..."
  systemctl disable --now ${SERVICE_TUN} ${SERVICE_WEB} >/dev/null 2>&1 || true

  echo "Cleaning old main configs..."
  rm -f "$CORE_MAIN" "$CONF_IR_MAIN" "$CONF_KH_MAIN" "$CONF_ZEX_MAIN"

  run_wizard

  echo "Re-enabling and restarting services..."
  systemctl enable ${SERVICE_TUN} ${SERVICE_WEB} >/dev/null 2>&1 || true
  systemctl restart ${SERVICE_TUN} ${SERVICE_WEB} || true
}

# -------------------- Entry --------------------
main() {
  ensure_layout
  require_file "$CORE_SRC"
  require_file "$CONF_IR_SRC"
  require_file "$CONF_KH_SRC"

  if [[ "${1:-}" == "--reconfigure" ]]; then
    reconfigure_flow
    exit 0
  fi

  install_deps
  write_units
  write_panel

  # Warn if expected files are missing (do not abort)
  for f in "$BIN_TUN" "$BIN_WEB"; do
    [[ -f "$f" ]] || echo "Warning: Expected file not found yet: $f"
  done

  run_wizard

  chmod +x "$BIN_TUN" 2>/dev/null || true

  systemctl restart ${SERVICE_TUN} ${SERVICE_WEB} || true
  systemctl enable  ${SERVICE_TUN} ${SERVICE_WEB} >/dev/null 2>&1 || true

  echo
  echo "Installation complete. Run 'zt' to open the panel."
  echo "Log saved at: $LOG_FILE"
}

main "$@"
