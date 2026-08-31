#!/usr/bin/env bash
# install.sh: get a fresh device from "just cloned this repo" to "running
# opencode here bootstraps a real Agent ID Card and defaults to OpenCode
# Zen" in one command.
#
# What this does NOT do: clone the repo. R2R_Communicate is private, so
# there is no auth-free one-liner that could -- you still need to get the
# code onto the device yourself first, with your own git/gh credentials
# (SSH key, PAT, or `gh auth login`), the same way you would for any
# private repo:
#   git clone git@github.com:Jayasuryamahadevan/R2R_Communicate.git
#   # or: gh repo clone Jayasuryamahadevan/R2R_Communicate
# Everything AFTER that -- Python/Node prerequisites, the fasp_harness
# venv, OpenCode itself -- is what this script automates.
#
# Safe to re-run: every step checks whether it's already satisfied before
# doing anything. Nothing here touches system package sources (no apt
# repo additions) -- it tells you the one command to run yourself if a
# prerequisite is missing, rather than reconfiguring your package
# manager on your behalf.
#
# Usage: ./install.sh [-y]
#   -y   don't pause for confirmation before each optional install step

set -euo pipefail

ASSUME_YES=0
if [[ "${1:-}" == "-y" ]]; then
	ASSUME_YES=1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
info() { printf '  %s\n' "$1"; }
ok() { printf '  \033[32m\xe2\x9c\x93\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }

confirm() {
	local prompt="$1"
	if [[ "$ASSUME_YES" == "1" ]]; then
		return 0
	fi
	read -r -p "  $prompt [y/N] " reply
	[[ "$reply" =~ ^[Yy]$ ]]
}

bold "R2R_Communicate install"
info "repo root: $REPO_ROOT"
info "platform: $(uname -s) $(uname -m)"
echo

# --- Python 3.11+ for fasp_harness ------------------------------------
bold "1/5 Python (for fasp_harness)"
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3; do
	if command -v "$candidate" >/dev/null 2>&1; then
		version=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
		major=${version%%.*}
		minor=${version##*.}
		if [[ "$major" == "3" && "$minor" -ge 11 ]]; then
			PYTHON_BIN="$candidate"
			break
		fi
	fi
done
if [[ -z "$PYTHON_BIN" ]]; then
	warn "No Python 3.11+ found."
	info "Install it yourself first, then re-run this script:"
	info "  Debian/Ubuntu/Raspberry Pi OS: sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
	info "  macOS (Homebrew):              brew install python@3.12"
	exit 1
fi
ok "found $PYTHON_BIN ($($PYTHON_BIN --version 2>&1))"

if [[ ! -d .venv ]]; then
	info "creating .venv..."
	"$PYTHON_BIN" -m venv .venv
fi
# shellcheck source=/dev/null
source .venv/bin/activate
info "installing fasp_harness (editable) into .venv..."
pip install --quiet --upgrade pip
pip install --quiet -e .
ok "fasp_harness installed -- try: .venv/bin/python -m fasp_harness.discovery --help"
deactivate
echo

# --- Node 20+ for bridge_core / the bridges ---------------------------
bold "2/5 Node.js (for bridge_core, pi_bridge, opencode_bridge)"
NODE_OK=0
if command -v node >/dev/null 2>&1; then
	node_major=$(node --version | sed -E 's/^v([0-9]+).*/\1/')
	if [[ "$node_major" -ge 20 ]]; then
		NODE_OK=1
		ok "found node $(node --version)"
	fi
fi
if [[ "$NODE_OK" == "0" ]]; then
	warn "No Node.js 20+ found."
	info "Install it yourself first, then re-run this script. On Debian/Ubuntu/Raspberry Pi OS:"
	info "  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -"
	info "  sudo apt install -y nodejs"
	info "(nodesource adds an apt source -- deliberately not run automatically by this script.)"
	exit 1
fi
echo

# --- OpenCode itself ----------------------------------------------------
bold "3/5 OpenCode (the primary agent host -- opencode_bridge needs it)"
if command -v opencode >/dev/null 2>&1; then
	ok "found opencode $(opencode --version 2>/dev/null | tail -1)"
elif confirm "OpenCode isn't installed. Install it now via the official installer (curl -fsSL https://opencode.ai/install | bash)?"; then
	curl -fsSL https://opencode.ai/install | bash
	ok "OpenCode installed"
else
	warn "Skipped. Install later with: curl -fsSL https://opencode.ai/install | bash"
fi
echo

# --- pi (optional second bridge) ---------------------------------------
bold "4/5 pi coding agent (optional -- only needed for pi_bridge)"
if command -v pi >/dev/null 2>&1; then
	ok "found pi $(pi --version 2>/dev/null || echo installed)"
elif confirm "pi isn't installed. Install @earendil-works/pi-coding-agent globally via npm now?"; then
	npm install --global --ignore-scripts @earendil-works/pi-coding-agent
	ok "pi installed"
else
	warn "Skipped. Install later with: npm install --global --ignore-scripts @earendil-works/pi-coding-agent"
fi
echo

# --- Bridge dependencies -------------------------------------------------
bold "5/5 Bridge dependencies (npm install for each bridge's own package.json)"
for bridge_dir in opencode_bridge/plugin pi_bridge/extension; do
	if [[ -f "$bridge_dir/package.json" ]]; then
		info "npm install in $bridge_dir ..."
		(cd "$bridge_dir" && npm install --silent)
		ok "$bridge_dir ready"
	fi
done
echo

bold "Done."
info "This repo's own opencode.json already wires opencode_bridge in by default."
info "Next: cd $REPO_ROOT && opencode models"
info "  -- that one command bootstraps this device's own real Agent ID Card"
info "     (.aic/, gitignored) and confirms OpenCode Zen works with zero API keys."
