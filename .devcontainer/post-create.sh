#!/usr/bin/env bash
# Installs the tools the devcontainer features do not cover, from pinned releases with
# checksum verification. Same versions tier0.yml uses in CI.
set -euo pipefail

CONFTEST_VERSION=0.56.0
GITLEAKS_VERSION=8.21.2
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo ">> apt: zip, jq"
sudo apt-get update -qq
sudo apt-get install -y -qq zip jq >/dev/null

echo ">> conftest ${CONFTEST_VERSION}"
F="conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz"
curl -sSLO "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/${F}"
curl -sSL "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/checksums.txt" \
  | grep " ${F}$" | sha256sum -c -
tar xzf "$F" conftest && sudo install -m 0755 conftest /usr/local/bin/conftest

echo ">> gitleaks ${GITLEAKS_VERSION}"
F="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
curl -sSLO "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${F}"
curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
  | grep " ${F}$" | sha256sum -c -
tar xzf "$F" gitleaks && sudo install -m 0755 gitleaks /usr/local/bin/gitleaks

echo ">> python: lab dependencies (Lab 4 seed script)"
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet azure-cosmos azure-identity

echo ">> az: log-analytics extension (Lab 2 query), no prompt later"
az extension add --name log-analytics --only-show-errors || true

cd - >/dev/null
bash .devcontainer/verify-tools.sh
cat <<'MSG'

Workstation ready. Sign in to Azure from here with:

  az login --use-device-code

Then start at docs/SETUP.md step 2 (provider registration).
MSG
