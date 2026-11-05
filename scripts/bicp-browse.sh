#!/bin/bash

./scripts/bicp2hex.sh | \
    fzf --wrap  \
      --header 'Select BICP message to inspect (Enter to exit with selection, Esc to cancel)' \
      --preview 'echo {} | python3 protococo.py find --cocofile=protocols/bicp/bicp_stack.coco --dissect --decode --format=tree --field-bytes-limit=8' \
      --preview-window 'right:70%:wrap' \
      --bind 'alt-u:preview-up' \
      --bind 'alt-d:preview-down'
