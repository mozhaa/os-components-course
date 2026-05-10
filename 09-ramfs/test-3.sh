#!/bin/sh

set -ex

# load module
insmod my_ramfs.ko

# mount filesystem
mkdir -p /mnt/my_ramfs
mount -t my_ramfs none /mnt/my_ramfs
ls -laid /mnt/my_ramfs

cd /mnt/my_ramfs

# create file
touch myfile
ls -lai

# rename file
mv myfile myrenamedfile
ls -lai

# create link to file
ln myrenamedfile mylink
ls -lai

# read/write file
echo "message" > myrenamedfile
cat myrenamedfile

# remove link to file
rm mylink
ls -la

# delete file
rm -f myrenamedfile
ls -la

# unmount filesystem
cd ..
umount /mnt/my_ramfs

# unload module
rmmod my_ramfs
