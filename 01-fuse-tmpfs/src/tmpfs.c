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

static int tmpfs_getattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi) {
    (void)fi;

    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(&state->root, path);
    if (!inode) {
        return -ENOENT;
    }

    memset(statbuf, 0, sizeof(struct stat));

    statbuf->st_mode = inode->mode;
    statbuf->st_uid = inode->uid;
    statbuf->st_gid = inode->gid;
    statbuf->st_atime = inode->atime;
    statbuf->st_mtime = inode->mtime;
    statbuf->st_ctime = inode->ctime;
    statbuf->st_blksize = 4096;

    if (S_ISDIR(inode->mode)) {
        statbuf->st_nlink = 2 + inode->content.dir.subdir_count;
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

static int tmpfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *dir = find_inode(&state->root, path);
    if (!dir) {
        return -ENOENT;
    }
    if (!S_ISDIR(dir->mode)) {
        return -ENOTDIR;
    }

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
    if (ret != 0) {
        return ret;
    }
    if (existing != NULL) {
        return -EEXIST;
    }
    if (parent == NULL) {
        return -EINVAL;
    }

    if (parent->content.dir.entries_size == parent->content.dir.entries_capacity) {
        int new_cap = parent->content.dir.entries_capacity * 2;
        struct tmpfs_dirent *new_entries = realloc(parent->content.dir.entries, new_cap * sizeof(struct tmpfs_dirent));
        if (!new_entries) {
            return -ENOMEM;
        }
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

static int tmpfs_open(const char *path, struct fuse_file_info *fi) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(&state->root, path);
    if (!inode) {
        return -ENOENT;
    }
    if (S_ISDIR(inode->mode)) {
        return -EISDIR;
    }
    return 0;
}

static int tmpfs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(&state->root, path);
    if (!inode) {
        return -ENOENT;
    }

    time_t now = time(NULL);

    if (tv == NULL) {
        inode->atime = now;
        inode->mtime = now;
    } else {
        if (tv[0].tv_nsec == UTIME_NOW) {
            inode->atime = now;
        } else if (tv[0].tv_nsec != UTIME_OMIT) {
            inode->atime = tv[0].tv_sec;
        }

        if (tv[1].tv_nsec == UTIME_NOW) {
            inode->mtime = now;
        } else if (tv[1].tv_nsec != UTIME_OMIT) {
            inode->mtime = tv[1].tv_sec;
        }
    }

    inode->ctime = now;
    return 0;
}

static int tmpfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(&state->root, path);
    if (!inode) {
        return -ENOENT;
    }
    if (!S_ISREG(inode->mode)) {
        return -EINVAL;
    }

    if (offset >= inode->content.file.size) {
        return 0;
    }

    size_t available = inode->content.file.size - offset;
    size_t to_copy = size < available ? size : available;
    memcpy(buf, inode->content.file.data + offset, to_copy);

    inode->atime = time(NULL);

    return to_copy;
}

static int tmpfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(&state->root, path);
    if (!inode) {
        return -ENOENT;
    }
    if (!S_ISREG(inode->mode)) {
        return -EINVAL;
    }

    size_t new_size = offset + size;
    if (new_size > inode->content.file.size) {
        char *new_data = realloc(inode->content.file.data, new_size);
        if (!new_data) {
            return -ENOMEM;
        }
        inode->content.file.data = new_data;
        if (offset > inode->content.file.size) {
            memset(inode->content.file.data + inode->content.file.size, 0, offset - inode->content.file.size);
        }
        inode->content.file.size = new_size;
    }

    memcpy(inode->content.file.data + offset, buf, size);
    time_t now = time(NULL);
    inode->mtime = now;
    inode->ctime = now;

    return size;
}

static int tmpfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(&state->root, path);
    if (!inode) {
        return -ENOENT;
    }
    if (!S_ISREG(inode->mode)) {
        return -EINVAL;
    }

    if (size == 0) {
        free(inode->content.file.data);
        inode->content.file.data = NULL;
        inode->content.file.size = 0;
    } else if (size < inode->content.file.size) {
        char *new_data = realloc(inode->content.file.data, size);
        if (!new_data && size > 0) {
            return -ENOMEM;
        }
        inode->content.file.data = new_data;
        inode->content.file.size = size;
    } else if (size > inode->content.file.size) {
        char *new_data = realloc(inode->content.file.data, size);
        if (!new_data) {
            return -ENOMEM;
        }
        memset(new_data + inode->content.file.size, 0, size - inode->content.file.size);
        inode->content.file.data = new_data;
        inode->content.file.size = size;
    }

    inode->ctime = time(NULL);
    inode->mtime = inode->ctime;
    return 0;
}

static void init_dir(struct tmpfs_inode *inode, int mode) {
    inode->mode = S_IFDIR | (mode & 07777);
    inode->uid = getuid();
    inode->gid = getgid();
    time_t now = time(NULL);
    inode->atime = now;
    inode->mtime = now;
    inode->ctime = now;

    inode->content.dir.entries = malloc(16 * sizeof(struct tmpfs_dirent));
    inode->content.dir.entries_size = 0;
    inode->content.dir.entries_capacity = 16;
    inode->content.dir.subdir_count = 0;
}

static int tmpfs_mkdir(const char *path, mode_t mode) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *parent;
    char name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *existing;

    int ret = path_lookup(&state->root, path, &parent, name, &existing);
    if (ret != 0) {
        return ret;
    }
    if (existing != NULL) {
        return -EEXIST;
    }
    if (parent == NULL) {
        return -EINVAL;
    }

    if (parent->content.dir.entries_size == parent->content.dir.entries_capacity) {
        int new_cap = parent->content.dir.entries_capacity * 2;
        struct tmpfs_dirent *new_entries = realloc(parent->content.dir.entries, new_cap * sizeof(struct tmpfs_dirent));
        if (!new_entries) {
            return -ENOMEM;
        }
        parent->content.dir.entries = new_entries;
        parent->content.dir.entries_capacity = new_cap;
    }

    struct tmpfs_dirent *new_entry = &parent->content.dir.entries[parent->content.dir.entries_size];
    strncpy(new_entry->name, name, TMPFS_NAME_MAX_LENGTH);
    new_entry->name[TMPFS_NAME_MAX_LENGTH] = '\0';

    struct tmpfs_inode *inode = &new_entry->inode;
    init_dir(inode, mode);

    parent->content.dir.entries_size++;
    parent->content.dir.subdir_count++;
    parent->mtime = inode->ctime;
    parent->ctime = inode->ctime;

    return 0;
}

static int tmpfs_rmdir(const char *path) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *parent;
    char name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *child;

    int ret = path_lookup(&state->root, path, &parent, name, &child);
    if (ret != 0) {
        return ret;
    }
    if (child == NULL) {
        return -ENOENT;
    }
    if (!S_ISDIR(child->mode)) {
        return -ENOTDIR;
    }
    if (child->content.dir.entries_size != 0) {
        return -ENOTEMPTY;
    }
    if (parent == NULL) {
        return -EBUSY;
    }

    int index = -1;
    for (int i = 0; i < parent->content.dir.entries_size; i++) {
        if (strcmp(parent->content.dir.entries[i].name, name) == 0) {
            index = i;
            break;
        }
    }
    if (index == -1) {
        return -ENOENT;
    }

    free(child->content.dir.entries);

    for (int i = index; i < parent->content.dir.entries_size - 1; i++) {
        parent->content.dir.entries[i] = parent->content.dir.entries[i + 1];
    }
    parent->content.dir.entries_size--;
    parent->content.dir.subdir_count--;

    time_t now = time(NULL);
    parent->mtime = now;
    parent->ctime = now;

    return 0;
}

static int tmpfs_unlink(const char *path) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *parent;
    char name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *child;

    int ret = path_lookup(&state->root, path, &parent, name, &child);
    if (ret != 0) {
        return ret;
    }
    if (child == NULL) {
        return -ENOENT;
    }
    if (!S_ISREG(child->mode)) {
        return -EISDIR;
    }
    if (parent == NULL) {
        return -EBUSY;
    }

    int index = -1;
    for (int i = 0; i < parent->content.dir.entries_size; i++) {
        if (strcmp(parent->content.dir.entries[i].name, name) == 0) {
            index = i;
            break;
        }
    }
    if (index == -1) {
        return -ENOENT;
    }

    free(child->content.file.data);

    for (int i = index; i < parent->content.dir.entries_size - 1; i++) {
        parent->content.dir.entries[i] = parent->content.dir.entries[i + 1];
    }
    parent->content.dir.entries_size--;

    time_t now = time(NULL);
    parent->mtime = now;
    parent->ctime = now;

    return 0;
}

static void tmpfs_destroy(void *private_data) {
    struct tmpfs_state *state = TMPFS_DATA;
    // TODO: recursively free all inodes
    free(state);
}

struct fuse_operations tmpfs_oper = {
    .getattr = tmpfs_getattr,
    .readdir = tmpfs_readdir,
    .mknod = tmpfs_mknod,
    .open = tmpfs_open,
    .read = tmpfs_read,
    .write = tmpfs_write,
    .truncate = tmpfs_truncate,
    .utimens = tmpfs_utimens,
    .mkdir = tmpfs_mkdir,
    .rmdir = tmpfs_rmdir,
    .unlink = tmpfs_unlink,
    .destroy = tmpfs_destroy,
};

int main(int argc, char *argv[]) {
    if ((getuid() == 0) || (geteuid() == 0)) {
        fprintf(stderr, "Running tmpfs as root is not allowed\n");
        return -1;
    }

    struct tmpfs_state *state = malloc(sizeof(struct tmpfs_state));
    init_dir(&state->root, 0755);

    return fuse_main(argc, argv, &tmpfs_oper, state);
}
