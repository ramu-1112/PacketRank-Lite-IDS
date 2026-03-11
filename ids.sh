#! /bin/bash
cd "${dirname "$0"}"
pip install -r requirements.txt

sudo python3 main.py
