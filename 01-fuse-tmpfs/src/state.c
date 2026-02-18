#include "state.h"

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
        if (!(current->mode & S_IFDIR)) {
            free(path_copy);
            return NULL;
        }

        struct tmpfs_dirent *entries = current->content.dir.entries;
        int found = 0;
        for (int i = 0; i < current->content.dir.entries_size; i++) {
            if (strcmp(entries[i].name, token) == 0) {
                current = entries[i].inode;
                found = 1;
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