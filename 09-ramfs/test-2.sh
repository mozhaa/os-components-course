#!/bin/sh

set -x

# load module
insmod my_ramfs.ko

# mount filesystem
mkdir -p /mnt/my_ramfs
mount -t my_ramfs none /mnt/my_ramfs
ls -laid /mnt/my_ramfs

cd /mnt/my_ramfs

# create directory
mkdir mydir
ls -la

# create subdirectory
cd mydir
mkdir mysubdir
ls -lai

# rename subdirectory
mv mysubdir myrenamedsubdir
ls -lai

# delete renamed subdirectory
rmdir myrenamedsubdir
ls -la

# create file
touch myfile
ls -lai

# rename file
mv myfile myrenamedfile
ls -lai

# delete renamed file
rm myrenamedfile

# delete directory
cd ..
rmdir mydir
ls -la

# unmount filesystem
cd ..
umount /mnt/my_ramfs

# unload module
rmmod my_ramfs
