#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "params.h"
#include "state.h"

#include <fuse.h>

int tmpfs_getattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi) {
    (void)fi;

    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(&state->root, path);
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
        // TODO: count only subdirectories
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

int tmpfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi,
                  enum fuse_readdir_flags flags) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *dir = find_inode(&state->root, path);
    if (!dir)
        return -ENOENT;
    if (!S_ISDIR(dir->mode))
        return -ENOTDIR;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    for (int i = 0; i < dir->content.dir.entries_size; i++) {
        struct tmpfs_dirent *entry = &dir->content.dir.entries[i];
        filler(buf, entry->name, NULL, 0, 0);
    }

    return 0;
}

static int tmpfs_mknod(const char *path, mode_t mode, dev_t dev) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *parent;
    char name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *existing;

    int ret = path_lookup(&state->root, path, &parent, name, &existing);
    if (ret != 0)
        return ret;
    if (existing != NULL)
        return -EEXIST;
    if (parent == NULL)
        return -EINVAL;

    if (parent->content.dir.entries_size == parent->content.dir.entries_capacity) {
        int new_cap = parent->content.dir.entries_capacity * 2;
        struct tmpfs_dirent *new_entries = realloc(parent->content.dir.entries, new_cap * sizeof(struct tmpfs_dirent));
        if (!new_entries)
            return -ENOMEM;
        parent->content.dir.entries = new_entries;
        parent->content.dir.entries_capacity = new_cap;
    }

    struct tmpfs_dirent *new_entry = &parent->content.dir.entries[parent->content.dir.entries_size];
    strncpy(new_entry->name, name, TMPFS_NAME_MAX_LENGTH);
    new_entry->name[TMPFS_NAME_MAX_LENGTH] = '\0';

    struct tmpfs_inode *inode = &new_entry->inode;
    inode->mode = mode;
    inode->uid = getuid();
    inode->gid = getgid();
    time_t now = time(NULL);
    inode->atime = now;
    inode->mtime = now;
    inode->ctime = now;

    if (S_ISREG(mode)) {
        inode->content.file.size = 0;
        inode->content.file.data = NULL;
    } else {
        inode->content.file.size = 0;
        inode->content.file.data = NULL;
    }

    parent->content.dir.entries_size++;
    return 0;
}

void tmpfs_destroy(void *private_data) {
    struct tmpfs_state *state = TMPFS_DATA;
    // TODO: recursively free all inodes
    free(state);
}

struct fuse_operations tmpfs_oper = {
    .getattr = tmpfs_getattr,
    .readdir = tmpfs_readdir,
    .mknod = tmpfs_mknod,
    .destroy = tmpfs_destroy,
};

int main(int argc, char *argv[]) {
    if ((getuid() == 0) || (geteuid() == 0)) {
        fprintf(stderr, "Running tmpfs as root is not allowed\n");
        return -1;
    }

    struct tmpfs_state *state = malloc(sizeof(struct tmpfs_state));
    state->root.mode = S_IFDIR | 0755;
    state->root.uid = getuid();
    state->root.gid = getgid();
    time_t now = time(NULL);
    state->root.atime = now;
    state->root.mtime = now;
    state->root.ctime = now;
    state->root.content.dir.entries = malloc(16 * sizeof(struct tmpfs_dirent));
    state->root.content.dir.entries_size = 0;
    state->root.content.dir.entries_capacity = 16;

    return fuse_main(argc, argv, &tmpfs_oper, state);
}
