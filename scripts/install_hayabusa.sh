#!/usr/bin/env bash
# Downloads the latest Hayabusa release for this platform and extracts it to ./hayabusa/
set -euo pipefail

REPO="Yamato-Security/hayabusa"
DEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/hayabusa"

case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64) SUFFIX="mac-aarch64.zip" ;;
      *) SUFFIX="mac-x64.zip" ;;
    esac
    ;;
  Linux)
    case "$(uname -m)" in
      aarch64|arm64) SUFFIX="lin-aarch64-gnu.zip" ;;
      *) SUFFIX="lin-x64-gnu.zip" ;;
    esac
    ;;
  *)
    echo "Unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

echo "Detected asset suffix: $SUFFIX"

DOWNLOAD_URL=$(curl -sL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep "browser_download_url" \
  | grep "$SUFFIX" \
  | grep -v "live-response" \
  | grep -v "all-platforms" \
  | head -n 1 \
  | cut -d '"' -f 4)

if [ -z "$DOWNLOAD_URL" ]; then
  echo "Could not find a release asset ending in $SUFFIX" >&2
  exit 1
fi

echo "Downloading $DOWNLOAD_URL ..."
TMP_ZIP="$(mktemp -t hayabusa).zip"
curl -sL -o "$TMP_ZIP" "$DOWNLOAD_URL"

echo "Extracting to $DEST_DIR ..."
mkdir -p "$DEST_DIR"
unzip -o -q "$TMP_ZIP" -d "$DEST_DIR"
rm -f "$TMP_ZIP"

chmod +x "$DEST_DIR"/hayabusa-* 2>/dev/null || true

BINARY=$(find "$DEST_DIR" -maxdepth 1 -type f -name "hayabusa-*" | head -n 1)
if [ -n "$BINARY" ]; then
  ln -sf "$(basename "$BINARY")" "$DEST_DIR/hayabusa"
fi

echo "Done. Hayabusa installed in $DEST_DIR (stable path: $DEST_DIR/hayabusa)"
