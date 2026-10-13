#!/usr/bin/env bash

OS="$(uname)"

if [ "$OS" = "Darwin" ]; then
  # macOS: try Bottle sound, fall back to bell.
  if command -v afplay >/dev/null 2>&1; then
    afplay /System/Library/Sounds/Bottle.aiff >/dev/null 2>&1 || printf '\a'
  else
    printf '\a'
  fi
else
  # Linux / anything else: terminal bell.
  printf '\a'
fi

exit 0
