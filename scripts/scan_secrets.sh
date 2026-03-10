#!/bin/bash
# NHI Secret Pattern Scanner
# Scans known credential file paths for hardcoded secrets.
# Designed to run as a Wazuh full_command localfile monitor.
#
# Output format: one line per match, suitable for Wazuh rules 100900-100914.
# Wazuh will generate rule 530/531 events from this output.

SCAN_PATHS=(
  /app/.env /app/.env.local /app/.env.production /app/.env.development
  /opt/.env /root/.env
  /root/.aws/credentials /root/.aws/config
  /root/.npmrc /root/.docker/config.json
  /root/.git-credentials /root/.gitconfig
  /runner/_work
)

PATTERNS=(
  'AKIA[0-9A-Z]{16}'
  'ASIA[0-9A-Z]{16}'
  'ghp_[a-zA-Z0-9]{36}'
  'gho_[a-zA-Z0-9]{36}'
  'ghs_[a-zA-Z0-9]{36}'
  'github_pat_[a-zA-Z0-9_]{22,}'
  'sk-[a-zA-Z0-9]{20,}'
  'xox[baprs]-[0-9]+'
  'sk_live_[0-9a-zA-Z]{24,}'
  'hvs\.[a-zA-Z0-9_-]{24,}'
  'atlasv1\.[a-zA-Z0-9_-]{40,}'
  'DefaultEndpointsProtocol=https;AccountName='
  'AIza[0-9A-Za-z\-_]{35}'
)

COMBINED_PATTERN=$(printf '%s|' "${PATTERNS[@]}")
COMBINED_PATTERN="${COMBINED_PATTERN%|}"

FOUND=0
for path in "${SCAN_PATHS[@]}"; do
  if [ -f "$path" ]; then
    matches=$(grep -EnH "$COMBINED_PATTERN" "$path" 2>/dev/null | head -5)
    if [ -n "$matches" ]; then
      echo "$matches"
      FOUND=1
    fi
  elif [ -d "$path" ]; then
    matches=$(find "$path" -maxdepth 2 -type f \( -name "*.env" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.cfg" -o -name "*.conf" \) 2>/dev/null | head -10 | xargs grep -EnH "$COMBINED_PATTERN" 2>/dev/null | head -5)
    if [ -n "$matches" ]; then
      echo "$matches"
      FOUND=1
    fi
  fi
done

if [ $FOUND -eq 0 ]; then
  echo "no_secrets_found"
fi
