#!/usr/bin/env bash

url="https://discord.com/api/download?platform=linux&format=deb"
curl -L -o ./install/discord.deb $url
sudo apt install ./install/discord.deb