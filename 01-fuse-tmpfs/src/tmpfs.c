#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

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