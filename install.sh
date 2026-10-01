#!/usr/bin/env bash
set -euo pipefail

tmp_dir=
staged_file=
cleanup() {
  if [[ -n "$staged_file" ]]; then rm -f -- "$staged_file"; fi
  if [[ -n "$tmp_dir" ]]; then rm -rf -- "$tmp_dir"; fi
}

fail() {
  printf 'portal installer: %s\n' "$*" >&2
  exit 1
}

download() {
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 "$@"
}

main() {
  local os arch asset version release_url expected actual hash filename install_dir
  command -v curl >/dev/null || fail 'curl is required'
  if ! command -v sha256sum >/dev/null && ! command -v shasum >/dev/null; then
    fail 'sha256sum or shasum is required to verify downloads'
  fi
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) fail 'only Linux and macOS are supported' ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail 'only amd64 and arm64 are supported' ;;
  esac
  asset="portal-$os-$arch"
  version="${PORTAL_VERSION:-}"
  if [[ -z "$version" ]]; then
    # Resolve once so the binary and checksum come from the same immutable release.
    release_url=$(download --head --output /dev/null --write-out '%{url_effective}' \
      https://github.com/lab47/portal/releases/latest) || fail 'could not resolve the latest release (a published release is required)'
    case "$release_url" in
      https://github.com/lab47/portal/releases/tag/*) version="${release_url##*/}" ;;
      *) fail 'GitHub did not redirect to a release tag' ;;
    esac
  fi
  [[ "$version" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]] || fail 'invalid release tag'
  install_dir="${PORTAL_INSTALL_DIR:-${HOME:?HOME must be set}/.local/bin}"
  [[ ! -d "$install_dir/portal" ]] || fail 'the destination portal is a directory'
  tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/portal-install.XXXXXX")
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  release_url="https://github.com/lab47/portal/releases/download/$version"
  printf 'Installing portal %s (%s/%s)...\n' "$version" "$os" "$arch"
  download --output "$tmp_dir/SHA256SUMS" "$release_url/SHA256SUMS"
  download --output "$tmp_dir/portal" "$release_url/$asset"
  expected=
  while read -r hash filename; do
    if [[ "$filename" == "$asset" ]]; then
      [[ -z "$expected" ]] || fail 'duplicate checksum entry'
      expected="$hash"
    fi
  done < "$tmp_dir/SHA256SUMS"
  [[ "$expected" =~ ^[a-f0-9]{64}$ ]] || fail "no valid checksum for $asset"
  if command -v sha256sum >/dev/null; then
    actual=$(sha256sum "$tmp_dir/portal")
  else
    actual=$(shasum -a 256 "$tmp_dir/portal")
  fi
  [[ "${actual%% *}" == "$expected" ]] || fail 'checksum mismatch; not installing'
  mkdir -p -- "$install_dir"
  # Stage on the destination filesystem, then replace atomically after verification.
  staged_file=$(mktemp "$install_dir/.portal.XXXXXX")
  cp -- "$tmp_dir/portal" "$staged_file"
  chmod 755 "$staged_file"
  mv -f -- "$staged_file" "$install_dir/portal"
  staged_file=
  printf 'Installed %s/portal\n' "$install_dir"
  case ":${PATH:-}:" in
    *":$install_dir:"*) ;;
    *) printf 'Add it to your PATH:\n  export PATH=%q:"$PATH"\n' "$install_dir" ;;
  esac
}

# Keep execution at the end so a truncated curl download cannot start installation.
main
