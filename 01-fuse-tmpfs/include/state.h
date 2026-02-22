#ifndef TMPFS_STATE_H_
#define TMPFS_STATE_H_

#include <sys/types.h>

#include "params.h"

#include <fuse.h>

struct tmpfs_inode {
    int mode;
    uid_t uid;
    gid_t gid;
    time_t atime, mtime, ctime;

    union {
        struct {
            size_t size;
            char *data;
        } file;
        struct {
            struct tmpfs_dirent *entries;
            int entries_size;
            int entries_capacity;
        } dir;
    } content;
};

struct tmpfs_dirent {
    char *name;
    struct tmpfs_inode *inode;
};

struct tmpfs_state {
    struct tmpfs_inode *root;
};

#define TMPFS_DATA ((struct tmpfs_state *)fuse_get_context()->private_data)

struct tmpfs_inode *find_inode(struct tmpfs_inode *root, const char *path);

#endif // TMPFS_STATE_H_
