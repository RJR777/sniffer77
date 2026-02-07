#!/bin/bash
# Wrapper script to run the network monitor with sudo using the virtual environment

if [ "$EUID" -ne 0 ]; then
  echo "Please run with sudo: sudo ./run.sh"
  exit 1
fi

# Get the directory of the script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Run with the virtual environment's python
$DIR/.venv/bin/python $DIR/main.py "$@"
