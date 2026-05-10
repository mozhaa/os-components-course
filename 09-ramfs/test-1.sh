#!/bin/sh

set -ex

#load module
insmod my_ramfs.ko

#mount filesystem
mkdir -p /mnt/my_ramfs
mount -t my_ramfs none /mnt/my_ramfs

#show registered filesystems
cat /proc/filesystems | grep my_ramfs

#show mounted filesystems
cat /proc/mounts | grep my_ramfs

#show filesystem statistics
stat -f /mnt/my_ramfs

#list all filesystem files
cd /mnt/my_ramfs
ls -la

#unmount filesystem
cd ..
umount /mnt/my_ramfs

#unload module
rmmod my_ramfs
