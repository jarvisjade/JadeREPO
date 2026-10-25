#!/usr/bin/bash
# See LICENSE file for copyright and license details.
# verify.sh: print fragment options that the final kernel .config lacks.
set -euo pipefail
config=$1
shift
status=0
while IFS= read -r line; do
    [[ "$line" =~ ^CONFIG_([A-Za-z0-9_]+)=(.*)$ ]] || continue
    name=${BASH_REMATCH[1]} want=${BASH_REMATCH[2]}
    have=$(sed -n "s/^CONFIG_$name=//p" "$config")
    [[ "$want" == n && -z "$have" || "$have" == "$want" ]] && continue
    printf 'kernel config: CONFIG_%s=%s requested, got %s\n' "$name" "$want" "${have:-n}" >&2
    status=1
done < <(cat "$@")
exit "$status"
