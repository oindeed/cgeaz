#!/usr/bin/env bash
# Proves the workstation has every tool the labs call. Run by post-create.sh and by
# .github/workflows/devcontainer.yml, so a broken image fails in CI, not mid-lab.
set -uo pipefail
FAIL=0
check() {
  if out=$("$@" 2>&1 | head -1); then echo "  ok   $1: $out"; else echo "  FAIL $1"; FAIL=1; fi
}
echo "== lab workstation tools =="
check az version --query '"azure-cli"' -o tsv
check terraform version
check tflint --version
check conftest --version
check gitleaks version
check python3 --version
check python3 -c "import azure.cosmos, azure.identity; print('azure-cosmos + azure-identity importable')"
check zip -v
check jq --version
check git --version
exit $FAIL
