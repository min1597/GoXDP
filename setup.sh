#!/bin/bash

if [ "$(uname -s)" != "Linux" ]; then
  echo "Error: This script is designed to run on Linux systems only."
  exit 1
fi

if ! grep -q "Ubuntu" /etc/os-release; then
  echo "Error: This script is designed for Ubuntu systems only."
  exit 1
fi

echo "Ubuntu system detected. Proceeding with setup..."

echo "Installing required packages..."
sudo apt-get update > /dev/null 2>&1
sudo apt-get install -y golang-go clang llvm linux-headers-$(uname -r) libbpf-dev gcc-multilib > /dev/null 2>&1

echo "Running 'go generate' in ./server directory..."
cd ./server || { echo "Directory ./server not found! Exiting."; exit 1; }
go generate > /dev/null 2>&1
cd .. || exit

echo "Building Go project..."
env CGO_ENABLED=0 GOOS=linux go build -o goxdp ./server/ > /dev/null 2>&1

echo "Setup complete."
