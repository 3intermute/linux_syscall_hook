#!/bin/bash

sudo apt update
# vm to host comm
sudo apt install spice-vdagent spice-webdavd davfs2 tasksel ubuntu-desktop
# kernel module shit
sudo apt install flex bison git build-essential linux-source linux-headers-$(uname -r)


cat << EOF | sudo tee -a /etc/fstabssu

http://localhost:9843 /mnt/dav davfs _netdev,user,exec 0 0
EOF


cat << EOF | sudo tee -a /etc/davfs2/secrets

/mnt/dav junk password
EOF




cat << EOF | sudo tee -a ~/.bashrc

alias compile_rk="cd /mnt/dav/rootkit; sudo -s; make all"
EOF
