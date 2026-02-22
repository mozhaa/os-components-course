#ifndef TMPFS_STATE_H_
#define TMPFS_STATE_H_

#include <sys/stat.h>
#include <sys/types.h>

#include "params.h"

#include <fuse.h>

#define TMPFS_NAME_MAX_LENGTH 63

struct tmpfs_inode {
    int mode;
    uid_t uid;
    gid_t gid;
    time_t atime, mtime, ctime;
    nlink_t nlink;
    int freed;

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
        struct {
            char *target;
        } symlink;
    } content;
};

struct tmpfs_dirent {
    char name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *inode;
};

struct tmpfs_state {
    struct tmpfs_inode *root;
};

#define TMPFS_DATA ((struct tmpfs_state *)fuse_get_context()->private_data)

int path_lookup(struct tmpfs_inode *root, const char *path, struct tmpfs_inode **parent, char *name,
                struct tmpfs_inode **child);

struct tmpfs_inode *find_inode(struct tmpfs_inode *root, const char *path);

#endif // TMPFS_STATE_H_
