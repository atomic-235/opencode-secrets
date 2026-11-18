#!/usr/bin/env sh
# Install the opencode-secrets plugin.
#
#   curl -fsSL https://raw.githubusercontent.com/atomic-235/opencode-secrets/main/install.sh | sh
#   ./install.sh uninstall
#
# Copies one file into $XDG_CONFIG_HOME/opencode/plugins/. No config edits, no build,
# no package manager, no service.
set -eu

repo="atomic-235/opencode-secrets"
ref="${SECRETS_REF:-main}"
config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
plugins_dir="$config_dir/plugins"
commands_dir="$config_dir/commands"
target="$plugins_dir/secrets.ts"

cleanup_dir=""
cleanup() {
  [ -n "$cleanup_dir" ] && [ -d "$cleanup_dir" ] && rm -rf "$cleanup_dir"
  return 0
}
trap cleanup EXIT

usage() {
  echo "usage: $0 [install|uninstall]" >&2
  exit 1
}

uninstall() {
  if [ -f "$target" ]; then
    rm -f "$target" "$config_dir/commands/mask.md"
    echo "Removed $target and $config_dir/commands/mask.md"
    echo "Restart OpenCode to unload it: opencode service restart"
  else
    echo "Nothing to remove at $target"
  fi
}

download() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    echo "ERROR: curl or wget is required" >&2
    exit 1
  fi
}

install() {
  here=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || pwd)

  if [ -f "$here/index.ts" ]; then
    source_file="$here/index.ts"
    source_command="$here/commands/mask.md"
  else
    cleanup_dir="${TMPDIR:-/tmp}/opencode-secrets-$$"
    mkdir -p "$cleanup_dir"
    archive="$cleanup_dir/source.tar.gz"
    echo "Downloading opencode-secrets from github.com/$repo"
    download "https://github.com/$repo/archive/refs/heads/$ref.tar.gz" "$archive"
    tar -xzf "$archive" -C "$cleanup_dir"
    source_dir=$(find "$cleanup_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)
    source_file="$source_dir/index.ts"
    source_command="$source_dir/commands/mask.md"
    if [ ! -f "$source_file" ]; then
      echo "ERROR: downloaded archive did not contain index.ts" >&2
      exit 1
    fi
  fi

  mkdir -p "$plugins_dir" "$commands_dir"
  cp "$source_file" "$target"
  cp "$source_command" "$commands_dir/mask.md"
  echo "Installed $target"
  echo "Installed $commands_dir/mask.md"
  echo
  echo "Next:"
  echo "  1. Restart OpenCode:  opencode service restart"
  echo "  2. Enable masking:    /mask on"
  echo "  3. Check the state:   /mask status"
}

case "${1:-install}" in
  install) install ;;
  uninstall | remove) uninstall ;;
  -h | --help | help) usage ;;
  *) usage ;;
esac
