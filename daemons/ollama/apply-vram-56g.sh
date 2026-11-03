#!/bin/bash
LABEL="com.vram.limit"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_PLIST="$SCRIPT_DIR/${LABEL}.plist"
LAUNCH_DAEMONS_DIR="/Library/LaunchDaemons"
TARGET_PLIST="$LAUNCH_DAEMONS_DIR/${LABEL}.plist"

echo "Set VRAM limit to 56GB for smooth LLM operation"
echo ""
echo "==> Installing $LABEL daemon..."

sudo cp $SOURCE_PLIST $TARGET_PLIST
sudo chown root:wheel $TARGET_PLIST
sudo chmod 644 $TARGET_PLIST
sudo launchctl load $TARGET_PLIST

echo "==> $LABEL successfully installed."