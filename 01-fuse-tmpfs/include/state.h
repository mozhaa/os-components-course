#ifndef TMPFS_STATE_H_
#define TMPFS_STATE_H_

struct tmpfs_state {};
#define TMPFS_DATA ((struct tmpfs_state *)fuse_get_context()->private_data)

#endif // TMPFS_STATE_H_
