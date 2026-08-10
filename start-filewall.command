#!/bin/bash
# Double-click this file to start the FileWall server on your Mac.
# It opens a Terminal window that stays open while the server runs.
# Close that window (or press Ctrl+C in it) to stop the server.
cd "$(dirname "$0")"
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed. Get the LTS installer from https://nodejs.org then run this again."
  read -n 1 -s -r -p "Press any key to close..."
  exit 1
fi
exec node server.mjs "$@"
