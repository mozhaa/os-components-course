#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "params.h"
#include "state.h"

#include <fuse.h>

int tmpfs_getattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi) {
    (void)fi;

    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(state->root, path);
    if (!inode)
        return -ENOENT;

    memset(statbuf, 0, sizeof(struct stat));

    statbuf->st_mode = inode->mode;
    statbuf->st_uid = inode->uid;
    statbuf->st_gid = inode->gid;
    statbuf->st_atime = inode->atime;
    statbuf->st_mtime = inode->mtime;
    statbuf->st_ctime = inode->ctime;
    statbuf->st_blksize = 4096;

    if (S_ISDIR(inode->mode)) {
        statbuf->st_nlink = 2 + inode->content.dir.entries_size;
        statbuf->st_size = 4096;
        statbuf->st_blocks = 8;
    } else if (S_ISREG(inode->mode)) {
        statbuf->st_nlink = 1;
        statbuf->st_size = inode->content.file.size;
        statbuf->st_blocks = (inode->content.file.size + 511) / 512;
    } else {
        return -EINVAL;
    }

    return 0;
}

struct fuse_operations tmpfs_oper = {.getattr = tmpfs_getattr};

int main(int argc, char *argv[]) {
    if ((getuid() == 0) || (geteuid() == 0)) {
        fprintf(stderr, "Running tmpfs as root is not allowed\n");
        return -1;
    }

    struct tmpfs_inode *root = malloc(sizeof(struct tmpfs_inode));
    root->mode = __S_IFDIR;
    struct tmpfs_state state = {.root = root};

    return fuse_main(argc, argv, &tmpfs_oper, &state);
}
