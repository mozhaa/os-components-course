#include "state.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct tmpfs_inode *find_inode(struct tmpfs_inode *root, const char *path) {
    if (strcmp(path, "/") == 0)
        return root;

    char *path_copy = strdup(path);
    if (!path_copy)
        return NULL;

    struct tmpfs_inode *current = root;
    char *saveptr;
    char *token = strtok_r(path_copy, "/", &saveptr);

    while (token) {
        if (!S_ISDIR(current->mode)) {
            free(path_copy);
            return NULL;
        }

        struct tmpfs_dirent *entries = current->content.dir.entries;
        bool found = false;
        for (int i = 0; i < current->content.dir.entries_size; i++) {
            if (strncmp(entries[i].name, token, TMPFS_NAME_MAX_LENGTH) == 0) {
                current = &entries[i].inode;
                found = true;
                break;
            }
        }

        if (!found) {
            free(path_copy);
            return NULL;
        }

        token = strtok_r(NULL, "/", &saveptr);
    }

    free(path_copy);
    return current;
}