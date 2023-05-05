#!/bin/bash
# MANAGED BY MES AIDES OPS

set -e

cd `dirname $0`

echo "Your SSH connection triggered a shell script ($0 $@)."
case "$1" in
    deploy)
        cd ops
        fab refresh --identity $HOME/.ssh/id_rsa --application $2
        ;;
    *)
        echo $"Usage: deploy"
        exit 1
esac