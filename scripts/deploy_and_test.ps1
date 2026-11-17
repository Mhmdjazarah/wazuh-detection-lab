# Deploy the detection lab rules into the Wazuh Docker manager and run all tests.
# Usage (PowerShell, from the repo folder):
#   powershell -ExecutionPolicy Bypass -File .\scripts\deploy_and_test.ps1
param(
    [string]$Container = "single-node-wazuh.manager-1"
)
$ErrorActionPreference = "Continue"
$Repo = Split-Path -Parent $PSScriptRoot

Write-Host "[1/4] Copying project into $Container ..." -ForegroundColor Cyan
docker exec $Container rm -rf /tmp/dl
docker cp "$Repo" "${Container}:/tmp/dl"

Write-Host "[2/4] Installing rules and checking config ..." -ForegroundColor Cyan
docker exec $Container bash -c 'rm -f /var/ossec/etc/rules/100000-logtest_eventchannel_shim.xml; cp /tmp/dl/rules/*.xml /tmp/dl/tests/fixtures/*.xml /var/ossec/etc/rules/ && chown wazuh:wazuh /var/ossec/etc/rules/1*.xml && chmod 660 /var/ossec/etc/rules/1*.xml && /var/ossec/bin/wazuh-analysisd -t'
if ($LASTEXITCODE -ne 0) { Write-Host "Rule syntax error - manager NOT restarted" -ForegroundColor Red; exit 1 }

Write-Host "[3/4] Restarting Wazuh manager ..." -ForegroundColor Cyan
docker exec $Container /var/ossec/bin/wazuh-control restart | Out-Null
Start-Sleep -Seconds 40

Write-Host "[4/4] Running detection tests ..." -ForegroundColor Cyan
docker exec $Container bash -c 'cd /tmp/dl && /var/ossec/framework/python/bin/python3 scripts/run_tests.py > /tmp/dl/test-output.txt 2>&1; cat /tmp/dl/test-output.txt'
docker cp "${Container}:/tmp/dl/test-output.txt" "$Repo\test-output.txt" | Out-Null
docker cp "${Container}:/tmp/dl/test-results.json" "$Repo\test-results.json" | Out-Null
