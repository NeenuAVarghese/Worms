#!/bin/bash

wget http://emerald.ecs.fullerton.edu/samples.tar
tar -xvf samples.tar
rm samples.tar
sudo apt-get install vim
sudo apt-get update
sudo apt-get install python-pip libffi-dev libssl-dev
sudo apt-get install python-paramiko
sudo apt-get install nmap
sudo apt-get install python-nmap
sudo apt-get install python-dev
sudo pip install netifaces
sudo apt-get install ia32-libs
sudo apt-get install g++
sudo apt-get install libssh-dev
sudo apt-get install libcurl4-openssl-dev
