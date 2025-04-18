#!/bin/bash

# 更新 apt 套件列表
echo "Updating apt package list..."
apt update

# 安裝必要的軟件包
echo "Installing required packages..."
apt install software-properties-common iproute2 nano -y

# 添加 Python PPA
echo "Adding deadsnakes PPA for Python 3.10..."
add-apt-repository ppa:deadsnakes/ppa -y

# 再次更新 apt 套件列表
echo "Updating apt package list again..."
apt update

# 安裝 Python 3.10 及相關套件
echo "Installing Python 3.10 and related packages..."
apt install python3.10 python3.10-venv python3.10-dev -y

# 安裝 pip
echo "Installing pip for Python 3..."
apt-get install python3-pip -y

# complie tool
echo "complie tool install..."
apt update && apt install -y clang llvm libbpf-dev gcc make iproute2 tcpdump iperf3

# BCC
apt-get install bpfcc-tools -y

# 檢查 Python 版本
echo "Checking Python version..."
python3 --version
# pip install
python3.8 -m pip install pyroute2==0.5.18

echo "Setup complete!"