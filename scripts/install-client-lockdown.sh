#!/bin/sh
set -eu
action=install
case "${1:-}" in
    --update) action=update; shift ;;
    --uninstall) action=uninstall; shift ;;
esac
exec /usr/bin/python3 -I "$(dirname "$0")/server-package.py" "$action" --client "$@"
