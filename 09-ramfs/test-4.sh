#!/bin/sh

set -e

cleanup() {
    cd / 2>/dev/null || true
    umount /mnt/my_ramfs 2>/dev/null || true
    rmmod my_ramfs 2>/dev/null || true
}
trap cleanup EXIT

# Load and mount
insmod my_ramfs.ko
mkdir -p /mnt/my_ramfs
mount -t my_ramfs none /mnt/my_ramfs
cd /mnt/my_ramfs

# ------------------------------------------------------------
# Test helper: compare two files
# ------------------------------------------------------------
cmp_file() {
    if ! cmp -s "$1" "$2"; then
        echo "ERROR: Files differ: $1 vs $2"
        ls -l "$1" "$2"
        exit 1
    fi
}

# ------------------------------------------------------------
# Test 1: small file (with newline)
# ------------------------------------------------------------
echo "Test 1: small file"
printf "Hello, my_ramfs!\n" > file1
printf "Hello, my_ramfs!\n" > /tmp/exp.$$
cmp_file file1 /tmp/exp.$$
sync
cmp_file file1 /tmp/exp.$$
rm /tmp/exp.$$

# ------------------------------------------------------------
# Test 2: 4KB of 'A' (repetitive, good RLE)
# ------------------------------------------------------------
echo "Test 2: 4KB repetitive"
dd if=/dev/zero bs=4096 count=1 2>/dev/null | tr '\0' 'A' > file2
dd if=/dev/zero bs=4096 count=1 2>/dev/null | tr '\0' 'A' > /tmp/exp.$$
cmp_file file2 /tmp/exp.$$
sync
cmp_file file2 /tmp/exp.$$
rm /tmp/exp.$$

# ------------------------------------------------------------
# Test 3: random binary data (4KB)
# ------------------------------------------------------------
echo "Test 3: random binary data"
dd if=/dev/urandom of=file3 bs=1024 count=4 2>/dev/null
dd if=file3 of=file3_copy bs=1024 count=4 2>/dev/null
cmp_file file3 file3_copy
sync
cmp_file file3 file3_copy
rm -f file3_copy

# ------------------------------------------------------------
# Test 4: write through hard link
# ------------------------------------------------------------
echo "Test 4: hard link"
printf "original\n" > original
ln original link
printf "updated\n" > link
printf "updated\n" > /tmp/exp.$$
cmp_file original /tmp/exp.$$
sync
cmp_file original /tmp/exp.$$
rm /tmp/exp.$$

# ------------------------------------------------------------
# Test 5: zero‑length file
# ------------------------------------------------------------
echo "Test 5: zero length"
> empty
[ ! -s empty ] || { echo "empty file not empty"; exit 1; }
sync
[ ! -s empty ]

# ------------------------------------------------------------
# Test 6: larger repetitive file (10KB) – exposes driver bug
# ------------------------------------------------------------
echo "Test 6: 10KB repetitive (stress test)"
dd if=/dev/zero bs=10240 count=1 2>/dev/null | tr '\0' 'X' > file4
dd if=/dev/zero bs=10240 count=1 2>/dev/null | tr '\0' 'X' > /tmp/exp.$$
# Check sizes first (will fail if driver truncates)
size_actual=$(stat -c %s file4)
size_expected=$(stat -c %s /tmp/exp.$$)
if [ "$size_actual" -ne "$size_expected" ]; then
    echo "FAIL: File size mismatch after write: expected $size_expected, got $size_actual"
    exit 1
fi
cmp_file file4 /tmp/exp.$$
sync
cmp_file file4 /tmp/exp.$$
rm /tmp/exp.$$

# ------------------------------------------------------------
# Test 7: multiple writes to same file
# ------------------------------------------------------------
echo "Test 7: multiple writes"
> multi
for i in $(seq 1 10); do
    printf "Line %d\n" $i >> multi
done
for i in $(seq 1 10); do
    printf "Line %d\n" $i
done > /tmp/exp.$$
cmp_file multi /tmp/exp.$$
sync
cmp_file multi /tmp/exp.$$
rm /tmp/exp.$$

# ------------------------------------------------------------
# Test 8: read beyond EOF
# ------------------------------------------------------------
echo "Test 8: read beyond EOF"
printf "short\n" > short
if dd if=short bs=1024 skip=1 2>/dev/null | grep -q '^'; then
    echo "FAIL: read beyond EOF returned data"
    exit 1
fi
sync
if dd if=short bs=1024 skip=1 2>/dev/null | grep -q '^'; then
    echo "FAIL: read beyond EOF returned data after sync"
    exit 1
fi

# ------------------------------------------------------------
echo "All tests completed successfully (driver is correct)."
exit 0