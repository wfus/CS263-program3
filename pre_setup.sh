#!/usr/bin/env bash

# Do NOT change this file!


set -e

sudo apt-get update -qq
sudo apt-get install -qq -- \
    build-essential \
    curl \
    gcc \
    gcc-multilib \
    libnet1-dev \
    libnet1-doc \
    libpcap-dev \
    nmap \
    openssl \
    python \
    python3 \
    python-pip \
    python3-pip \
    telnet \
    wget \
    wireshark \
;

pip install -U --user \
    requests \
;
pip3 install -U --user \
    dpkt \
    nose \
    requests \
;

# For Travis
sudo pip install -U \
    requests \
;
sudo pip3 install -U \
    dpkt \
    nose \
    requests \
;
