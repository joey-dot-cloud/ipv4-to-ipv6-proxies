#!/usr/bin/env bash
set -Eeuo pipefail

DEFAULT_START_PORT=30000

# -------- Logging --------
log() { printf '[%s] [INFO] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
warn() { printf '[%s] [WARN] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
error() { printf '[%s] [ERROR] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
debug() { if [ "${VERBOSE:-0}" = "1" ]; then printf '[%s] [DEBUG] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; fi; }

trap 'error "An unexpected error occurred at line $LINENO."' ERR

usage() {
	cat >&2 <<'USAGE'
Usage: 3proxy-random-ipv6-addresses.sh [options] [count] [user] [pass] [start_port] [iface]

Options:
  --install              Install 3proxy only and exit
  --uninstall            Uninstall 3proxy and exit
  --remove-ipv6 [IFACE]  Remove all global IPv6 /128 addresses from interface (default: auto-detect)
  -c, --count N         Number of IPv6 addresses to generate (overrides positional)
  -U, --user NAME       3proxy username
  -P, --pass PASS       3proxy password
  -s, --start-port N    Starting port (default: 30000)
  -i, --iface IFACE     Network interface to use
      --bind-ipv4 IP    IPv4 address to bind listeners (default: 0.0.0.0)
      --config-file P   3proxy config path (default: /etc/3proxy.cfg)
      --addr-file P     File to store generated IPv6 addresses (default: /etc/3proxy.ipv6)
      --log-file P      3proxy log file path (default: /var/log/3proxy.log)
  -t, --type TYPE       Proxy type: http or socks5 (default: http)
      --no-service      Do NOT create/manage a systemd service
      --skip-clean      Do NOT remove existing global /128 IPv6 addresses on the interface
  -v, --verbose         Enable verbose debug logs
  -h, --help            Show this help

Positional (legacy compatibility): count user pass start_port iface
USAGE
}

# -------- Defaults --------
COUNT_INPUT=""
USER_INPUT=""
PASS_INPUT=""
START_PORT_INPUT=""
IFACE_IN=""
SKIP_CLEAN=0
VERBOSE=0
NO_SERVICE=0
BIND_IP4="0.0.0.0"
CONFIG_FILE="/etc/3proxy.cfg"
ADDRS_FILE="/etc/3proxy.ipv6"
PROXY_LOG_FILE="/var/log/3proxy.log"
PROXY_TYPE_INPUT=""
INSTALL_ONLY=0
UNINSTALL_ONLY=0
REMOVE_IPV6_ONLY=0
REMOVE_IPV6_IFACE=""

# Parse options
while [ $# -gt 0 ]; do
	case "$1" in
		--install) INSTALL_ONLY=1; shift;;
		--uninstall) UNINSTALL_ONLY=1; shift;;
		--remove-ipv6) 
			REMOVE_IPV6_ONLY=1
			if [ $# -gt 1 ] && [[ "$2" != -* ]]; then
				REMOVE_IPV6_IFACE="$2"
				shift 2
			else
				shift
			fi
			;;
		-c|--count) COUNT_INPUT="$2"; shift 2;;
		-U|--user) USER_INPUT="$2"; shift 2;;
		-P|--pass) PASS_INPUT="$2"; shift 2;;
		-s|--start-port) START_PORT_INPUT="$2"; shift 2;;
		-i|--iface) IFACE_IN="$2"; shift 2;;
		--bind-ipv4) BIND_IP4="$2"; shift 2;;
		--config-file) CONFIG_FILE="$2"; shift 2;;
		--addr-file) ADDRS_FILE="$2"; shift 2;;
		--log-file) PROXY_LOG_FILE="$2"; shift 2;;
		-t|--type) PROXY_TYPE_INPUT="$2"; shift 2;;
		--no-service) NO_SERVICE=1; shift;;
		--skip-clean) SKIP_CLEAN=1; shift;;
		-v|--verbose) VERBOSE=1; shift;;
		-h|--help) usage; exit 0;;
		--) shift; break;;
		-*) echo "Unknown option: $1" >&2; usage; exit 2;;
		*) break;;
	esac
done

# Collect remaining positionals after options; only fill if still empty
if [ $# -gt 0 ] && [ -z "${COUNT_INPUT}" ]; then COUNT_INPUT="$1"; shift; fi
if [ $# -gt 0 ] && [ -z "${USER_INPUT}" ]; then USER_INPUT="$1"; shift; fi
if [ $# -gt 0 ] && [ -z "${PASS_INPUT}" ]; then PASS_INPUT="$1"; shift; fi
if [ $# -gt 0 ] && [ -z "${START_PORT_INPUT}" ]; then START_PORT_INPUT="$1"; shift; fi
if [ $# -gt 0 ] && [ -z "${IFACE_IN}" ]; then IFACE_IN="$1"; shift; fi

if [ "$(id -u)" -ne 0 ]; then
	echo "This script must be run as root." >&2
	exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
	echo "apt-get not found. This script supports Debian/Ubuntu." >&2
	exit 1
fi

if ! command -v ip >/dev/null 2>&1; then
	warn "'ip' command not found. Installing iproute2..."
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -y
	apt-get install -y iproute2
fi

# -------- Install 3proxy function --------
install_3proxy() {
	if command -v 3proxy >/dev/null 2>&1; then
		log "3proxy already installed at $(command -v 3proxy)."
		return 0
	fi
	
	log "Installing 3proxy..."
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -y
	apt-get install -y gcc make git
	WORKDIR="$(mktemp -d)"
	trap 'rm -rf "${WORKDIR}"; error "Cleanup after failure"' ERR
	git clone --depth 1 https://github.com/3proxy/3proxy.git "${WORKDIR}/3proxy"
	make -C "${WORKDIR}/3proxy" -f Makefile.Linux
	install -m 0755 "${WORKDIR}/3proxy/bin/3proxy" /usr/local/bin/3proxy
	rm -rf "${WORKDIR}"
	trap - ERR
	# restore global trap removed above
	trap 'error "An unexpected error occurred at line $LINENO."' ERR
	
	log "3proxy installed successfully at /usr/local/bin/3proxy"
	return 0
}

# -------- Uninstall 3proxy function --------
uninstall_3proxy() {
	log "Uninstalling 3proxy..."
	
	# Stop and disable systemd service if it exists
	if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
		if systemctl is-active --quiet 3proxy 2>/dev/null; then
			log "Stopping 3proxy service..."
			systemctl stop 3proxy
		fi
		if systemctl is-enabled --quiet 3proxy 2>/dev/null; then
			log "Disabling 3proxy service..."
			systemctl disable 3proxy
		fi
		if [ -f /etc/systemd/system/3proxy.service ]; then
			log "Removing systemd service file..."
			rm -f /etc/systemd/system/3proxy.service
			systemctl daemon-reload
		fi
	fi
	
	# Kill any running 3proxy processes
	if pgrep -x 3proxy >/dev/null 2>&1; then
		log "Killing running 3proxy processes..."
		pkill -x 3proxy
		sleep 2
		if pgrep -x 3proxy >/dev/null 2>&1; then
			warn "Some 3proxy processes may still be running"
		fi
	fi
	
	# Remove 3proxy binary
	PROXY_BIN="$(command -v 3proxy || true)"
	if [ -n "${PROXY_BIN}" ]; then
		log "Removing 3proxy binary: ${PROXY_BIN}"
		rm -f "${PROXY_BIN}"
	fi
	
	# Remove default config files if they exist
	if [ -f "/etc/3proxy.cfg" ]; then
		log "Removing config file: /etc/3proxy.cfg"
		rm -f "/etc/3proxy.cfg"
	fi
	
	if [ -f "/etc/3proxy.ipv6" ]; then
		log "Removing address file: /etc/3proxy.ipv6"
		rm -f "/etc/3proxy.ipv6"
	fi
	
	if [ -f "/var/log/3proxy.log" ]; then
		log "Removing log file: /var/log/3proxy.log"
		rm -f "/var/log/3proxy.log"
	fi
	
	log "3proxy uninstalled successfully"
	return 0
}

# -------- Remove IPv6 addresses function --------
remove_ipv6_addresses() {
	local target_iface="$1"
	
	# Auto-detect interface if not specified
	if [ -z "${target_iface}" ]; then
		target_iface="$(ip -6 route show default 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}' || true)"
	fi
	if [ -z "${target_iface}" ]; then
		target_iface="$(ip -6 addr show scope global | awk '
			/^[0-9]+: [^:]+:/ {iface=$2; sub(/:$/, "", iface); next}
			/inet6/ && /scope global/ {print iface; exit}
		' || true)"
	fi
	
	if [ -z "${target_iface}" ]; then
		echo "Failed to detect an interface with a global IPv6 address." >&2
		exit 1
	fi
	
	log "Removing global IPv6 /128 addresses from interface: ${target_iface}"
	
	# Find and remove all global /128 IPv6 addresses on the interface
	mapfile -t TO_REMOVE < <(
		ip -6 addr show dev "${target_iface}" scope global | awk '
			/inet6/ {
				split($2, a, "/")
				if (a[2]=="128") print $2
			}
		'
	)
	
	if [ "${#TO_REMOVE[@]}" -eq 0 ]; then
		log "No global IPv6 /128 addresses found to remove on ${target_iface}."
		return 0
	fi
	
	log "Found ${#TO_REMOVE[@]} global IPv6 /128 addresses to remove on ${target_iface}..."
	
	local removed_count=0
	for CIDR in "${TO_REMOVE[@]}"; do
		debug "Removing ${CIDR} from ${target_iface}..."
		if ip -6 addr del "${CIDR}" dev "${target_iface}"; then
			removed_count=$((removed_count + 1))
			debug "Successfully removed ${CIDR}"
		else
			warn "Failed to remove ${CIDR} from ${target_iface}"
		fi
	done
	
	log "Removed ${removed_count} out of ${#TO_REMOVE[@]} global IPv6 /128 addresses from ${target_iface}"
	return 0
}

# -------- Handle install/uninstall/remove-ipv6 modes --------
if [ "${INSTALL_ONLY}" -eq 1 ]; then
	install_3proxy
	exit 0
fi

if [ "${UNINSTALL_ONLY}" -eq 1 ]; then
	uninstall_3proxy
	exit 0
fi

if [ "${REMOVE_IPV6_ONLY}" -eq 1 ]; then
	remove_ipv6_addresses "${REMOVE_IPV6_IFACE}"
	exit 0
fi

prompt_nonempty() {
	local prompt var
	prompt="$1"
	while :; do
		read -rp "${prompt}" var || true
		if [ -n "${var}" ]; then
			printf "%s" "${var}"
			return 0
		fi
	done
}

prompt_silent_nonempty() {
	local prompt var
	prompt="$1"
	while :; do
		read -srp "${prompt}" var || true
		printf '\n' >&2
		if [ -n "${var}" ]; then
			printf "%s" "${var}"
			return 0
		fi
	done
}

prompt_with_default() {
	local prompt default var
	prompt="$1"
	default="$2"
	read -rp "${prompt}" var || true
	if [ -z "${var}" ]; then
		printf "%s" "${default}"
	else
		printf "%s" "${var}"
	fi
}

is_number() {
	[[ "$1" =~ ^[0-9]+$ ]]
}

# -------- Inputs --------
# Count first
if [ -z "${COUNT_INPUT}" ]; then
	COUNT_INPUT="$(prompt_nonempty "Enter number of IPv6 addresses to generate: ")"
fi
if ! is_number "${COUNT_INPUT}" || [ "${COUNT_INPUT}" -lt 1 ]; then
	echo "Invalid count. Must be a positive integer." >&2
	exit 1
fi

# Start port next
if [ -z "${START_PORT_INPUT}" ]; then
	START_PORT_INPUT="$(prompt_with_default "Enter start port [${DEFAULT_START_PORT}]: " "${DEFAULT_START_PORT}")"
fi
if ! is_number "${START_PORT_INPUT}" || [ "${START_PORT_INPUT}" -lt 1 ] || [ "${START_PORT_INPUT}" -gt 65535 ]; then
	echo "Invalid start port. Enter a number between 1 and 65535." >&2
	exit 1
fi

# Set COUNT/START_PORT and enforce max port range BEFORE credentials
COUNT="${COUNT_INPUT}"
START_PORT="${START_PORT_INPUT}"
MAX_LISTENERS=$(( 65535 - START_PORT + 1 ))
if [ "${COUNT}" -gt "${MAX_LISTENERS}" ]; then
	echo "Requested ${COUNT} listeners starting at port ${START_PORT} would exceed 65535. Maximum allowed is ${MAX_LISTENERS}." >&2
	exit 1
fi

# Select proxy type (default http)
if [ -z "${PROXY_TYPE_INPUT}" ]; then
	PROXY_TYPE_INPUT="$(prompt_with_default "Enter proxy type [http]: " "http")"
fi
raw_type="$(printf '%s' "${PROXY_TYPE_INPUT}" | tr '[:upper:]' '[:lower:]')"
case "${raw_type}" in
	http) PROXY_TYPE="http" ;;
	socks|socks5) PROXY_TYPE="socks5" ;;
	*) echo "Invalid proxy type. Must be 'http' or 'socks5'." >&2; exit 1 ;;
esac

# Credentials after port validation
if [ -z "${USER_INPUT}" ]; then
	USER_INPUT="$(prompt_nonempty "Enter 3proxy username: ")"
fi

if [ -z "${PASS_INPUT}" ]; then
	PASS_INPUT="$(prompt_silent_nonempty "Enter 3proxy password: ")"
fi

PROXY_USERNAME="$(printf '%s' "${USER_INPUT}" | tr -d '\r\n')"
PROXY_PASSWORD="$(printf '%s' "${PASS_INPUT}" | tr -d '\r\n')"

# -------- 3proxy install if missing --------
install_3proxy

PROXY_BIN="$(command -v 3proxy || true)"
if [ -z "${PROXY_BIN}" ]; then
	PROXY_BIN="/usr/local/bin/3proxy"
fi

# -------- Interface detection --------
IFACE="${IFACE_IN:-}"
if [ -z "${IFACE}" ]; then
	IFACE="$(ip -6 route show default 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}' || true)"
fi
if [ -z "${IFACE}" ]; then
	IFACE="$(ip -6 addr show scope global | awk '
		/^[0-9]+: [^:]+:/ {iface=$2; sub(/:$/, "", iface); next}
		/inet6/ && /scope global/ {print iface; exit}
	' || true)"
fi
if [ -z "${IFACE}" ]; then
	echo "Failed to detect an interface with a global IPv6 address." >&2
	exit 1
fi

# -------- Subnet detection --------
SUBNET="$(ip -6 route show dev "${IFACE}" | awk '$1 ~ /^[0-9a-fA-F:]+\/[0-9]+$/ && /proto kernel/ {print $1; exit}' || true)"
if [ -z "${SUBNET}" ]; then
	echo "Could not determine on-link IPv6 subnet for interface ${IFACE}." >&2
	exit 1
fi

NET="${SUBNET%/*}"
LEN="${SUBNET#*/}"

HOST_BITS=$((128 - LEN))
if [ "${HOST_BITS}" -le 0 ]; then
	echo "Prefix ${SUBNET} has no host space available." >&2
	exit 1
fi

if [ "${HOST_BITS}" -lt 16 ]; then
	MAX_HOST=$(( 1 << HOST_BITS ))
	if [ "${COUNT}" -gt "${MAX_HOST}" ]; then
		echo "Requested ${COUNT} addresses but only ${MAX_HOST} are available under ${SUBNET}." >&2
		exit 1
	fi
fi

log "Interface: ${IFACE}"
log "Subnet: ${SUBNET}"
log "Proxy type: ${PROXY_TYPE}"
log "Binding IPv4: ${BIND_IP4}"
log "Config file: ${CONFIG_FILE}"
log "Addr file: ${ADDRS_FILE}"
log "3proxy log file: ${PROXY_LOG_FILE}"

# -------- Optionally remove existing /128s on the selected interface only --------
if [ "${SKIP_CLEAN}" -eq 1 ]; then
	log "Skipping removal of existing global /128 IPv6 addresses on ${IFACE} (per --skip-clean)."
else
	remove_ipv6_addresses "${IFACE}"
fi

log "Adding ${COUNT} IPv6 /128 addresses on ${IFACE}..."

declare -a ADDED_ADDRS=()
ATTEMPTS=0
LIMIT=$(( COUNT * 20 ))
declare -A USED_ADDRS=()

# -------- IPv6 helpers --------
expand_ipv6() {
	local ip="$1"
	awk -v ip="$ip" '
function lcase(s,    r,i,c){r="";for(i=1;i<=length(s);i++){c=substr(s,i,1);r=r ((c>="A"&&c<="Z")?tolower(c):c)};return r}
BEGIN{
	s=ip
	n=split(s, parts, "::")
	left=parts[1]
	right=(n==2?parts[2]:"")
	nleft=(left==""?0:split(left, L, ":"))
	nright=(right==""?0:split(right, R, ":"))
	missing=8-(nleft+nright)
	outc=0
	for(i=1;i<=nleft;i++){h=L[i]; if(h=="") h="0"; h=lcase(h); x="0000"h; out[++outc]=substr(x, length(x)-3) }
	for(i=1;i<=missing;i++){ out[++outc]="0000" }
	for(i=1;i<=nright;i++){h=R[i]; if(h=="") h="0"; h=lcase(h); x="0000"h; out[++outc]=substr(x, length(x)-3) }
	if(n==1){
		outc=0
		nA=split(s, A, ":")
		for(i=1;i<=nA;i++){h=A[i]; if(h=="") h="0"; h=lcase(h); x="0000"h; out[++outc]=substr(x, length(x)-3) }
		for(;outc<8;){ out[++outc]="0000" }
	}
	for(i=1;i<=8;i++){ printf("%s%s", out[i], (i<8?":":"")) }
}' </dev/null
}

ipv6_to_bytes() {
	local ip="$1" exp
	exp="$(expand_ipv6 "$ip")"
	IFS=: read -r h1 h2 h3 h4 h5 h6 h7 h8 <<< "$exp"
	printf '%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n' \
		"${h1:0:2}" "${h1:2:2}" \
		"${h2:0:2}" "${h2:2:2}" \
		"${h3:0:2}" "${h3:2:2}" \
		"${h4:0:2}" "${h4:2:2}" \
		"${h5:0:2}" "${h5:2:2}" \
		"${h6:0:2}" "${h6:2:2}" \
		"${h7:0:2}" "${h7:2:2}" \
		"${h8:0:2}" "${h8:2:2}"
}

bytes_to_ipv6() {
	local bytes=("$@")
	local out=""
	for ((i=0;i<16;i+=2)); do
		local h="${bytes[i]}${bytes[i+1]}"
		if [ -n "${out}" ]; then out="${out}:"; fi
		out="${out}$(printf '%s' "${h}" | tr '[:upper:]' '[:lower:]')"
	done
	printf '%s\n' "${out}"
}

addr_exists_on_iface() {
	local target="$1" iface="$2"
	local target_exp
	target_exp="$(expand_ipv6 "${target}")"
	while read -r cidr; do
		local a="${cidr%%/*}"
		local exp
		exp="$(expand_ipv6 "${a}")"
		if [ "${exp}" = "${target_exp}" ]; then
			return 0
		fi
	done < <(ip -6 addr show dev "${iface}" scope global | awk '/inet6/ {print $2}')
	return 1
}

NET_BYTES_STR="$(ipv6_to_bytes "${NET}")"
BYTES_KEEP=$(( LEN / 8 ))
BITS_KEEP=$(( LEN % 8 ))

gen_random_ipv6_in_subnet() {
	local NETB
	read -r -a NETB <<< "${NET_BYTES_STR}"
	local RAND
	RAND=($(od -An -N16 -tx1 /dev/urandom | tr -s '[:space:]' ' '))
	local NEW=()
	local i
	for ((i=0;i<16;i++)); do
		if [ "${i}" -lt "${BYTES_KEEP}" ]; then
			NEW[i]="${NETB[i]}"
		elif [ "${i}" -eq "${BYTES_KEEP}" ] && [ "${BITS_KEEP}" -ne 0 ]; then
			local high_mask=$(( (255 << (8 - BITS_KEEP)) & 255 ))
			local low_mask=$(( 255 ^ high_mask ))
			local netv=$(( 16#${NETB[i]} ))
			local randv=$(( 16#${RAND[i]} ))
			local newv=$(( (netv & high_mask) | (randv & low_mask) ))
			NEW[i]=$(printf '%02x' "${newv}")
		else
			NEW[i]="${RAND[i]}"
		fi
	done
	bytes_to_ipv6 "${NEW[@]}"
}

# -------- Generation loop --------
while [ "${#ADDED_ADDRS[@]}" -lt "${COUNT}" ]; do
	addr="$(gen_random_ipv6_in_subnet)"
	if [ -n "${USED_ADDRS[${addr}]+x}" ]; then
		ATTEMPTS=$((ATTEMPTS + 1))
		[ "${ATTEMPTS}" -ge "${LIMIT}" ] && break
		continue
	fi
	if ip -6 addr add "${addr}/128" dev "${IFACE}" 2>/dev/null; then
		debug "Added ${addr}/128"
		ADDED_ADDRS+=("${addr}")
		USED_ADDRS["${addr}"]=1
	else
		if addr_exists_on_iface "${addr}" "${IFACE}"; then
			debug "Exists ${addr}/128 (using existing)"
			ADDED_ADDRS+=("${addr}")
			USED_ADDRS["${addr}"]=1
		else
			warn "Failed to add ${addr}/128"
		fi
	fi
	ATTEMPTS=$((ATTEMPTS + 1))
	[ "${ATTEMPTS}" -ge "${LIMIT}" ] && break
done

if [ "${#ADDED_ADDRS[@]}" -eq 0 ]; then
	echo "No usable IPv6 addresses available; aborting." >&2
	exit 1
fi

# Save addresses for reference
printf "%s\n" "${ADDED_ADDRS[@]}" > "${ADDRS_FILE}"
chmod 0600 "${ADDRS_FILE}"
log "Saved ${#ADDED_ADDRS[@]} IPv6 addresses to ${ADDRS_FILE}"

# -------- Build 3proxy configuration --------
if [ -f "${CONFIG_FILE}" ]; then
	TS="$(date +%Y%m%d-%H%M%S)"
	cp -a "${CONFIG_FILE}" "${CONFIG_FILE}.bak.${TS}"
	debug "Backed up existing ${CONFIG_FILE} to ${CONFIG_FILE}.bak.${TS}"
fi

{
	echo "# Auto-generated by 3proxy-random-ipv6-addresses.sh on $(date '+%Y-%m-%d %H:%M:%S')"
	echo "flush"
	echo "nscache 65536"
	echo 'logformat "L%Y-%m-%d %H:%M:%S %. %E %U %C:%c %R:%r %O %I %h %T"'
	echo "log ${PROXY_LOG_FILE} D"
	echo "rotate 30"
	echo
	printf "auth strong\n"
	printf "users %s:CL:%s\n" "${PROXY_USERNAME}" "${PROXY_PASSWORD}"
	echo
	port="${START_PORT}"
	if [ "${PROXY_TYPE}" = "http" ]; then
		PROXY_CMD="proxy"
	else
		PROXY_CMD="socks -5"
	fi
	for addr in "${ADDED_ADDRS[@]}"; do
		echo "${PROXY_CMD} -6 -i${BIND_IP4} -e${addr} -p${port}"
		port=$((port + 1))
	done
} > "${CONFIG_FILE}"

touch "${PROXY_LOG_FILE}"
chmod 0644 "${PROXY_LOG_FILE}"

# -------- systemd service (optional) --------
HAVE_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	HAVE_SYSTEMD=1
fi

if [ "${NO_SERVICE}" -eq 1 ]; then
	log "Skipping systemd service management (per --no-service)"
elif [ "${HAVE_SYSTEMD}" -eq 1 ]; then
	if [ -f /etc/systemd/system/3proxy.service ]; then
		TS="$(date +%Y%m%d-%H%M%S)"
		cp -a /etc/systemd/system/3proxy.service "/etc/systemd/system/3proxy.service.bak.${TS}"
		debug "Backed up existing systemd unit to /etc/systemd/system/3proxy.service.bak.${TS}"
	fi

	cat > /etc/systemd/system/3proxy.service <<EOF
[Unit]
Description=3proxy tiny proxy server
After=network.target

[Service]
ExecStart=${PROXY_BIN} "${CONFIG_FILE}"
Restart=always
LimitNOFILE=131072
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOF

	systemctl daemon-reload
	systemctl enable --now 3proxy
	systemctl restart 3proxy

	if ! systemctl is-active --quiet 3proxy; then
		echo "3proxy service failed to start. Check logs with: journalctl -u 3proxy -xe --no-pager" >&2
		exit 1
	fi
else
	warn "systemd not detected; skipping service creation. To run manually:"
	printf '  %s\n' "${PROXY_BIN} ${CONFIG_FILE} &"
fi

echo
log "3proxy configured."
echo "Username: ${PROXY_USERNAME}"
echo "Password: ${PROXY_PASSWORD}"
debug "Listeners:"
if [ "${VERBOSE:-0}" = "1" ]; then
    PORT_LIST_START="${START_PORT}"
    for ((i=0; i<${#ADDED_ADDRS[@]}; i++)); do
        echo "  ${BIND_IP4}:$((PORT_LIST_START + i)) -> external [${ADDED_ADDRS[$i]}]"
    done
fi

echo
debug "Current global IPv6 addresses on ${IFACE}:"
if [ "${VERBOSE:-0}" = "1" ]; then
	ip -6 addr show dev "${IFACE}" scope global
fi