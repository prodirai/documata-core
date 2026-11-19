#!/usr/bin/env bash
set -euo pipefail
# Pinned upstream release checksums verified against GitHub release asset metadata.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
case "${1:-}" in
  secrets)
    url=https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
    checksum=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
    binary=gitleaks ;;
  workflows)
    url=https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz
    checksum=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
    binary=actionlint ;;
  *) echo 'Usage: ci-tools.sh secrets|workflows' >&2; exit 2 ;;
esac
curl --fail --silent --show-error --location --retry 3 "$url" -o "$work/tool.tar.gz"
echo "$checksum  $work/tool.tar.gz" | sha256sum --check --status
tar -xzf "$work/tool.tar.gz" -C "$work" "$binary"
if [[ "$binary" == gitleaks ]]; then
  "$work/gitleaks" git --redact --no-banner --log-opts=--all .
else
  "$work/actionlint" -shellcheck= -pyflakes=
fi
