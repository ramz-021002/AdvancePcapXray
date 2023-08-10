#!/bin/bash

# Get the current date
current_date=$(date +%Y-%m-%d)

# Create the folder if it doesn't exist
folder_name="packets_$current_date"
if [ ! -d "$folder_name" ]; then
    mkdir "$folder_name"
fi

# Change directory to the created folder
cd "$folder_name"

# Execute the command
sudo zeek -i en0 -C -w capture.pcap

# Check if the day has changed
new_date=$(date +%Y-%m-%d)
while [ "$current_date" == "$new_date" ]; do
    sleep 10  # Adjust the time interval between checks if needed
    new_date=$(date +%Y-%m-%d)
done

# Restart the script with the new date
exec "$0"
