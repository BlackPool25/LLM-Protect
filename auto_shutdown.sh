#!/bin/bash

# Wait for 30 minutes
sleep 1800

# Go to project directory
cd /home/lightdesk/Projects/LLM-Protect/ || exit

# Git add + commit
git add .
git commit -m "Auto shutdown"

# Shutdown the system
sudo shutdown -h now
