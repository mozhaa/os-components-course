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

static void update_inode_mtime_ctime(struct tmpfs_inode *inode) {
    time_t now = time(NULL);
    inode->mtime = now;
    inode->ctime = now;
}

static struct tmpfs_inode *create_inode(mode_t mode) {
    struct tmpfs_inode *inode = malloc(sizeof(struct tmpfs_inode));
    if (!inode) {
        return NULL;
    }
    inode->mode = mode;
    struct fuse_context *ctx = fuse_get_context();
    if (ctx) {
        inode->uid = ctx->uid;
        inode->gid = ctx->gid;
    } else {
        inode->uid = getuid();
        inode->gid = getgid();
    }
    update_inode_mtime_ctime(inode);
    inode->atime = inode->mtime;

    if (S_ISDIR(mode)) {
        inode->nlink = 2;
        inode->content.dir.entries = malloc(16 * sizeof(struct tmpfs_dirent));
        if (!inode->content.dir.entries) {
            free(inode);
            return NULL;
        }
        inode->content.dir.entries_size = 0;
        inode->content.dir.entries_capacity = 16;
    } else if (S_ISREG(mode)) {
        inode->nlink = 1;
        inode->content.file.size = 0;
        inode->content.file.data = NULL;
    } else if (S_ISLNK(mode)) {
        inode->nlink = 1;
        inode->content.symlink.target = NULL;
    } else if (S_ISBLK(mode) || S_ISCHR(mode)) {
        inode->content.dev = 0;
        inode->nlink = 1;
    } else {
        inode->nlink = 1;
    }
    return inode;
}

static void free_inode_content(struct tmpfs_inode *inode) {
    if (S_ISDIR(inode->mode)) {
        free(inode->content.dir.entries);
    } else if (S_ISREG(inode->mode)) {
        free(inode->content.file.data);
    } else if (S_ISLNK(inode->mode)) {
        free(inode->content.symlink.target);
    }
}

static void recursive_free_inode(struct tmpfs_inode *inode) {
    if (!inode) {
        return;
    }

    if (S_ISDIR(inode->mode)) {
        for (int i = 0; i < inode->content.dir.entries_size; i++) {
            recursive_free_inode(inode->content.dir.entries[i].inode);
        }
    }
    free_inode_content(inode);
    free(inode);
}

static int add_dirent(struct tmpfs_inode *dir, const char *name, struct tmpfs_inode *inode) {
    if (dir->content.dir.entries_size == dir->content.dir.entries_capacity) {
        int new_cap = dir->content.dir.entries_capacity * 2;
        struct tmpfs_dirent *new_entries = realloc(dir->content.dir.entries, new_cap * sizeof(struct tmpfs_dirent));
        if (!new_entries) {
            return -ENOMEM;
        }
        dir->content.dir.entries = new_entries;
        dir->content.dir.entries_capacity = new_cap;
    }

    struct tmpfs_dirent *new_entry = &dir->content.dir.entries[dir->content.dir.entries_size];
    strncpy(new_entry->name, name, TMPFS_NAME_MAX_LENGTH);
    new_entry->name[TMPFS_NAME_MAX_LENGTH] = 0;
    new_entry->inode = inode;

    dir->content.dir.entries_size++;
    return 0;
}

static int tmpfs_getattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi) {
    fprintf(stderr, "tmpfs_getattr(path=%s, fi=%p)\n", path, (void *)fi);
    (void)fi;

    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(state->root, path);
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
    statbuf->st_nlink = inode->nlink;
    statbuf->st_blksize = 4096;

    if (S_ISDIR(inode->mode)) {
        statbuf->st_size = 4096;
        statbuf->st_blocks = 8;
    } else if (S_ISREG(inode->mode)) {
        statbuf->st_size = inode->content.file.size;
        statbuf->st_blocks = (inode->content.file.size + 511) / 512;
    } else if (S_ISLNK(inode->mode)) {
        statbuf->st_size = strlen(inode->content.symlink.target);
        statbuf->st_blocks = (statbuf->st_size + 511) / 512;
    } else if (S_ISBLK(inode->mode) || S_ISCHR(inode->mode)) {
        statbuf->st_rdev = inode->content.dev;
        statbuf->st_size = 0;
        statbuf->st_blocks = 0;
    } else {
        statbuf->st_size = 0;
        statbuf->st_blocks = 0;
    }

    return 0;
}

static int tmpfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
    fprintf(stderr, "tmpfs_readdir(path=%s, offset=%ld, fi=%p, flags=%d)\n", path, (long)offset, (void *)fi, flags);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *dir = find_inode(state->root, path);
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
    fprintf(stderr, "tmpfs_mknod(path=%s, mode=%o, dev=%ld)\n", path, mode, (long)dev);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *parent;
    char name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *existing;

    if (S_ISDIR(mode) || S_ISLNK(mode)) {
        return -EINVAL;
    }

    int ret = path_lookup(state->root, path, &parent, name, &existing);
    if (ret != 0) {
        return ret;
    }
    if (existing != NULL) {
        return -EEXIST;
    }
    if (parent == NULL) {
        return -EINVAL;
    }

    struct tmpfs_inode *inode = create_inode(mode);
    if (!inode) {
        return -ENOMEM;
    }

    if (S_ISBLK(mode) || S_ISCHR(mode)) {
        inode->content.dev = dev;
    }

    ret = add_dirent(parent, name, inode);
    if (ret != 0) {
        free(inode);
        return ret;
    }

    update_inode_mtime_ctime(parent);
    return 0;
}

static int tmpfs_open(const char *path, struct fuse_file_info *fi) {
    fprintf(stderr, "tmpfs_open(path=%s, fi=%p)\n", path, (void *)fi);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(state->root, path);
    if (!inode) {
        return -ENOENT;
    }
    if (S_ISDIR(inode->mode)) {
        return -EISDIR;
    }
    if (S_ISLNK(inode->mode)) {
        return -EINVAL;
    }
    return 0;
}

static int tmpfs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    fprintf(stderr, "tmpfs_utimens(path=%s, fi=%p)\n", path, (void *)fi);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(state->root, path);
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
    fprintf(stderr, "tmpfs_read(path=%s, size=%zu, offset=%ld, fi=%p)\n", path, size, (long)offset, (void *)fi);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(state->root, path);
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
    fprintf(stderr, "tmpfs_write(path=%s, size=%zu, offset=%ld, fi=%p)\n", path, size, (long)offset, (void *)fi);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(state->root, path);
    if (!inode) {
        return -ENOENT;
    }
    if (!S_ISREG(inode->mode)) {
        return -EINVAL;
    }

    size_t new_size = offset + size;
    if (new_size > inode->content.file.size) {
        size_t size_increase = new_size - inode->content.file.size;
        if (state->used_size + size_increase > state->max_size) {
            return -ENOSPC;
        }
        char *new_data = realloc(inode->content.file.data, new_size);
        if (!new_data) {
            return -ENOMEM;
        }
        inode->content.file.data = new_data;
        if (offset > inode->content.file.size) {
            memset(inode->content.file.data + inode->content.file.size, 0, offset - inode->content.file.size);
        }
        inode->content.file.size = new_size;
        state->used_size += size_increase;
    }

    memcpy(inode->content.file.data + offset, buf, size);
    update_inode_mtime_ctime(inode);

    return size;
}

static int tmpfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    fprintf(stderr, "tmpfs_truncate(path=%s, size=%ld, fi=%p)\n", path, (long)size, (void *)fi);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(state->root, path);
    if (!inode) {
        return -ENOENT;
    }
    if (!S_ISREG(inode->mode)) {
        return -EINVAL;
    }

    if (size == 0) {
        free(inode->content.file.data);
        inode->content.file.data = NULL;
        state->used_size -= inode->content.file.size;
        inode->content.file.size = 0;
    } else if (size < inode->content.file.size) {
        char *new_data = realloc(inode->content.file.data, size);
        if (!new_data && size > 0) {
            return -ENOMEM;
        }
        inode->content.file.data = new_data;
        state->used_size -= (inode->content.file.size - size);
        inode->content.file.size = size;
    } else if (size > inode->content.file.size) {
        size_t size_increase = size - inode->content.file.size;
        if (state->used_size + size_increase > state->max_size) {
            return -ENOSPC;
        }
        char *new_data = realloc(inode->content.file.data, size);
        if (!new_data) {
            return -ENOMEM;
        }
        memset(new_data + inode->content.file.size, 0, size - inode->content.file.size);
        inode->content.file.data = new_data;
        inode->content.file.size = size;
        state->used_size += size_increase;
    }

    update_inode_mtime_ctime(inode);
    return 0;
}

static int tmpfs_mkdir(const char *path, mode_t mode) {
    fprintf(stderr, "tmpfs_mkdir(path=%s, mode=%o)\n", path, mode);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *parent;
    char name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *existing;

    int ret = path_lookup(state->root, path, &parent, name, &existing);
    if (ret != 0) {
        return ret;
    }
    if (existing != NULL) {
        return -EEXIST;
    }
    if (parent == NULL) {
        return -EINVAL;
    }

    struct tmpfs_inode *inode = create_inode(S_IFDIR | (mode & 07777));
    if (!inode) {
        return -ENOMEM;
    }

    ret = add_dirent(parent, name, inode);
    if (ret != 0) {
        free_inode_content(inode);
        free(inode);
        return ret;
    }

    parent->nlink++;
    update_inode_mtime_ctime(parent);

    return 0;
}

static int tmpfs_rmdir(const char *path) {
    fprintf(stderr, "tmpfs_rmdir(path=%s)\n", path);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *parent;
    char name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *child;

    int ret = path_lookup(state->root, path, &parent, name, &child);
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

    free_inode_content(child);
    free(child);

    for (int i = index; i < parent->content.dir.entries_size - 1; i++) {
        parent->content.dir.entries[i] = parent->content.dir.entries[i + 1];
    }
    parent->content.dir.entries_size--;
    parent->nlink--;

    update_inode_mtime_ctime(parent);

    return 0;
}

static int tmpfs_unlink(const char *path) {
    fprintf(stderr, "tmpfs_unlink(path=%s)\n", path);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *parent;
    char name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *child;

    int ret = path_lookup(state->root, path, &parent, name, &child);
    if (ret != 0) {
        return ret;
    }
    if (child == NULL) {
        return -ENOENT;
    }
    if (S_ISDIR(child->mode)) {
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

    child->nlink--;
    if (child->nlink == 0) {
        if (S_ISREG(child->mode)) {
            state->used_size -= child->content.file.size;
        }
        free_inode_content(child);
        free(child);
    }

    for (int i = index; i < parent->content.dir.entries_size - 1; i++) {
        parent->content.dir.entries[i] = parent->content.dir.entries[i + 1];
    }
    parent->content.dir.entries_size--;

    update_inode_mtime_ctime(parent);

    return 0;
}

static int tmpfs_rename(const char *oldpath, const char *newpath, unsigned int flags) {
    fprintf(stderr, "tmpfs_rename(oldpath=%s, newpath=%s, flags=%u)\n", oldpath, newpath, flags);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *src_parent;
    char src_name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *src_inode;

    struct tmpfs_inode *dst_parent;
    char dst_name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *dst_inode;

    int ret = path_lookup(state->root, oldpath, &src_parent, src_name, &src_inode);
    if (ret != 0) {
        return ret;
    }
    if (src_inode == NULL) {
        return -ENOENT;
    }
    if (src_parent == NULL) {
        return -EINVAL;
    }

    ret = path_lookup(state->root, newpath, &dst_parent, dst_name, &dst_inode);
    if (ret != 0 && ret != -ENOENT) {
        return ret;
    }
    if (dst_parent == NULL) {
        return -EINVAL;
    }

    if (src_inode == dst_inode) {
        return 0;
    }

    if (dst_inode != NULL) {
        if (S_ISDIR(src_inode->mode) != S_ISDIR(dst_inode->mode)) {
            return -EINVAL;
        }
        if (S_ISDIR(dst_inode->mode) && dst_inode->content.dir.entries_size != 0) {
            return -ENOTEMPTY;
        }
    }

    if (S_ISDIR(src_inode->mode)) {
        size_t old_len = strlen(oldpath);
        if (strncmp(oldpath, newpath, old_len) == 0) {
            if (newpath[old_len] == '/') {
                return -EINVAL;
            } else if (newpath[old_len] == 0) {
                return 0;
            }
        }
    }

    if (dst_parent != src_parent) {
        if (dst_parent->content.dir.entries_size == dst_parent->content.dir.entries_capacity) {
            int new_cap = dst_parent->content.dir.entries_capacity * 2;
            struct tmpfs_dirent *new_entries =
                realloc(dst_parent->content.dir.entries, new_cap * sizeof(struct tmpfs_dirent));
            if (!new_entries) {
                return -ENOMEM;
            }
            dst_parent->content.dir.entries = new_entries;
            dst_parent->content.dir.entries_capacity = new_cap;
        }
    }

    int src_index = -1;
    for (int i = 0; i < src_parent->content.dir.entries_size; i++) {
        if (strcmp(src_parent->content.dir.entries[i].name, src_name) == 0) {
            src_index = i;
            break;
        }
    }
    if (src_index == -1) {
        return -ENOENT;
    }

    if (dst_inode != NULL) {
        int dst_index = -1;
        for (int i = 0; i < dst_parent->content.dir.entries_size; i++) {
            if (strcmp(dst_parent->content.dir.entries[i].name, dst_name) == 0) {
                dst_index = i;
                break;
            }
        }
        if (dst_index == -1) {
            return -ENOENT;
        }

        int dst_mode = dst_inode->mode;
        dst_inode->nlink--;
        if (dst_inode->nlink == 0) {
            free_inode_content(dst_inode);
            free(dst_inode);
        }

        for (int i = dst_index; i < dst_parent->content.dir.entries_size - 1; i++) {
            dst_parent->content.dir.entries[i] = dst_parent->content.dir.entries[i + 1];
        }
        dst_parent->content.dir.entries_size--;
        if (S_ISDIR(dst_mode)) {
            dst_parent->nlink--;
        }
        if (dst_parent == src_parent && src_index > dst_index) {
            src_index--;
        }
    }

    struct tmpfs_dirent src_entry = src_parent->content.dir.entries[src_index];

    for (int i = src_index; i < src_parent->content.dir.entries_size - 1; i++) {
        src_parent->content.dir.entries[i] = src_parent->content.dir.entries[i + 1];
    }
    src_parent->content.dir.entries_size--;

    if (S_ISDIR(src_inode->mode)) {
        src_parent->nlink--;
    }

    strncpy(src_entry.name, dst_name, TMPFS_NAME_MAX_LENGTH);
    src_entry.name[TMPFS_NAME_MAX_LENGTH] = 0;

    dst_parent->content.dir.entries[dst_parent->content.dir.entries_size] = src_entry;
    dst_parent->content.dir.entries_size++;

    if (S_ISDIR(src_inode->mode)) {
        dst_parent->nlink++;
    }

    update_inode_mtime_ctime(src_parent);
    if (dst_parent != src_parent) {
        update_inode_mtime_ctime(dst_parent);
    }
    src_inode->ctime = time(NULL);

    return 0;
}

static int tmpfs_symlink(const char *target, const char *linkpath) {
    fprintf(stderr, "tmpfs_symlink(target=%s, linkpath=%s)\n", target, linkpath);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *parent;
    char name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *existing;

    int ret = path_lookup(state->root, linkpath, &parent, name, &existing);
    if (ret != 0) {
        return ret;
    }
    if (existing != NULL) {
        return -EEXIST;
    }
    if (parent == NULL) {
        return -EINVAL;
    }

    struct tmpfs_inode *inode = create_inode(S_IFLNK | 0777);
    if (!inode) {
        return -ENOMEM;
    }

    char *target_copy = strdup(target);
    if (!target_copy) {
        free(inode);
        return -ENOMEM;
    }
    inode->content.symlink.target = target_copy;

    ret = add_dirent(parent, name, inode);
    if (ret != 0) {
        free(target_copy);
        free(inode);
        return ret;
    }

    update_inode_mtime_ctime(parent);

    return 0;
}

static int tmpfs_readlink(const char *path, char *buf, size_t size) {
    fprintf(stderr, "tmpfs_readlink(path=%s, size=%zu)\n", path, size);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(state->root, path);
    if (!inode) {
        return -ENOENT;
    }
    if (!S_ISLNK(inode->mode)) {
        return -EINVAL;
    }

    char *target = inode->content.symlink.target;
    size_t len = strlen(target);
    if (len >= size) {
        len = size - 1;
    }
    memcpy(buf, target, len);
    buf[len] = 0;
    return 0;
}

static int tmpfs_link(const char *oldpath, const char *newpath) {
    fprintf(stderr, "tmpfs_link(oldpath=%s, newpath=%s)\n", oldpath, newpath);
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *src_inode = find_inode(state->root, oldpath);
    if (!src_inode) {
        return -ENOENT;
    }
    if (S_ISDIR(src_inode->mode)) {
        return -EPERM;
    }

    struct tmpfs_inode *parent;
    char name[TMPFS_NAME_MAX_LENGTH + 1];
    struct tmpfs_inode *existing;

    int ret = path_lookup(state->root, newpath, &parent, name, &existing);
    if (ret != 0) {
        return ret;
    }
    if (existing != NULL) {
        return -EEXIST;
    }
    if (parent == NULL) {
        return -EINVAL;
    }

    ret = add_dirent(parent, name, src_inode);
    if (ret != 0) {
        return ret;
    }
    src_inode->nlink++;

    update_inode_mtime_ctime(parent);

    return 0;
}

static int tmpfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(state->root, path);
    if (!inode) {
        return -ENOENT;
    }
    if (uid != (uid_t)-1) {
        inode->uid = uid;
    }
    if (gid != (gid_t)-1) {
        inode->gid = gid;
    }
    inode->ctime = time(NULL);
    return 0;
}

static int tmpfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    struct tmpfs_state *state = TMPFS_DATA;
    struct tmpfs_inode *inode = find_inode(state->root, path);
    if (!inode) {
        return -ENOENT;
    }
    inode->mode = (inode->mode & S_IFMT) | (mode & 07777);
    inode->ctime = time(NULL);
    return 0;
}

static int tmpfs_statfs(const char *path, struct statvfs *st) {
    struct tmpfs_state *state = TMPFS_DATA;
    memset(st, 0, sizeof(*st));
    st->f_bsize = 4096;
    st->f_frsize = 4096;
    st->f_blocks = state->max_size / 4096;
    st->f_bfree = (state->max_size - state->used_size) / 4096;
    st->f_bavail = st->f_bfree;
    st->f_files = 1024 * 1024;
    st->f_ffree = st->f_files;
    st->f_favail = st->f_files;
    st->f_namemax = TMPFS_NAME_MAX_LENGTH;
    return 0;
}

static void tmpfs_destroy(void *private_data) {
    fprintf(stderr, "tmpfs_destroy(private_data=%p)\n", private_data);
    struct tmpfs_state *state = private_data;
    if (state->root) {
        recursive_free_inode(state->root);
    }
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
    .rename = tmpfs_rename,
    .symlink = tmpfs_symlink,
    .readlink = tmpfs_readlink,
    .link = tmpfs_link,
    .statfs = tmpfs_statfs,
    .chown = tmpfs_chown,
    .chmod = tmpfs_chmod,
    .destroy = tmpfs_destroy,
};

int main(int argc, char *argv[]) {
    if ((getuid() == 0) || (geteuid() == 0)) {
        fprintf(stderr, "Running tmpfs as root is not allowed\n");
        return -1;
    }

    struct tmpfs_state *state = malloc(sizeof(struct tmpfs_state));
    if (!state) {
        return -1;
    }
    state->root = create_inode(S_IFDIR | 0755);
    if (!state->root) {
        free(state);
        return -1;
    }
    state->max_size = 64 * 1024 * 1024;
    state->used_size = 0;

    return fuse_main(argc, argv, &tmpfs_oper, state);
}