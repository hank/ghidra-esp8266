#!/bin/bash
set -euo pipefail
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

GHIDRA_DIR=$(realpath "${1:?must pass ghidra release dir as first arg}")
shift

if [[ ! -d "$GHIDRA_DIR" ]]; then
    echo "GHIDRA_DIR not a valid directory"
    exit 5
fi


cd "$DIR/GhidraESP8266_2/"
rm -rf build dist
./gradlew -PGHIDRA_INSTALL_DIR="$GHIDRA_DIR" "$@"
cp "$DIR/GhidraESP8266_2/dist/ghidra_"*".zip" "$GHIDRA_DIR/Extensions/Ghidra/"
echo "Install the extension with the Ghidra 'Install Extensions' manager."
echo "Restart Ghidra"
