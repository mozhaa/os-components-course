#include "state.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int path_lookup(struct tmpfs_inode *root, const char *path, struct tmpfs_inode **parent, char *name,
                struct tmpfs_inode **child) {
    if (strcmp(path, "/") == 0) {
        if (parent) {
            *parent = NULL;
        }
        if (name) {
            name[0] = 0;
        }
        if (child) {
            *child = root;
        }
        return 0;
    }

    char *path_copy = strdup(path);
    if (!path_copy) {
        return -ENOMEM;
    }

    struct tmpfs_inode *current = root;
    struct tmpfs_inode *prev = NULL;
    char *saveptr;
    char *token = strtok_r(path_copy, "/", &saveptr);
    char *last_token = NULL;

    while (token) {
        last_token = token;

        if (!S_ISDIR(current->mode)) {
            free(path_copy);
            return -ENOTDIR;
        }

        struct tmpfs_dirent *entries = current->content.dir.entries;
        int i;
        for (i = 0; i < current->content.dir.entries_size; i++) {
            if (strcmp(entries[i].name, token) == 0)
                break;
        }

        if (i == current->content.dir.entries_size) {
            char *next = strtok_r(NULL, "/", &saveptr);
            if (next != NULL) {
                free(path_copy);
                return -ENOENT;
            } else {
                if (parent) {
                    *parent = current;
                }
                if (name) {
                    strncpy(name, token, TMPFS_NAME_MAX_LENGTH);
                    name[TMPFS_NAME_MAX_LENGTH] = 0;
                }
                if (child) {
                    *child = NULL;
                }
                free(path_copy);
                return 0;
            }
        } else {
            prev = current;
            current = entries[i].inode;
            token = strtok_r(NULL, "/", &saveptr);
        }
    }

    if (parent) {
        *parent = prev;
    }
    if (name) {
        strncpy(name, last_token, TMPFS_NAME_MAX_LENGTH);
        name[TMPFS_NAME_MAX_LENGTH] = 0;
    }
    if (child) {
        *child = current;
    }
    free(path_copy);
    return 0;
}

struct tmpfs_inode *find_inode(struct tmpfs_inode *root, const char *path) {
    struct tmpfs_inode *child;
    if (path_lookup(root, path, NULL, NULL, &child) != 0) {
        return NULL;
    }
    return child;
}
