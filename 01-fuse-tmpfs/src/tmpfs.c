#include <limits.h>
#include <sys/stat.h>

#include <params.h>
#include <state.h>

int bb_getattr(const char *path, struct stat *statbuf,
               struct fuse_file_info *fi) {
  return 0;
}