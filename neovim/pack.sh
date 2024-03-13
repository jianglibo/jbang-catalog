#!/bin/bash

# get this script's directory
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# let zip exclude git and node_modules

(cd $DIR && zip -r ./neovim.config.zip .config -x '*.git*' -x '*node_modules/*' -x '*/dist/*'  -x '.vscode/*' && cd -)
