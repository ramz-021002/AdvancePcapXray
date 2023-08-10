#!/bin/bash
trap "exit" INT
while true
do
    sudo python3 main.py
    sleep 10
done