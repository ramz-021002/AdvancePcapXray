#!/bin/bash
python3 Module/art.py
trap "exit" INT
while true
do
    sudo python3 main.py
    sleep 10
done
