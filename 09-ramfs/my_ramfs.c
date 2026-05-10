/*
 * SO2 Lab - Filesystem drivers
 * Exercise #1 (no-dev filesystem)
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mnt_idmapping.h>

MODULE_DESCRIPTION("my_ramfs");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_LICENSE("GPL");

#define my_ramfs_BLOCKSIZE		4096
#define my_ramfs_BLOCKSIZE_BITS	12
#define my_ramfs_MAGIC		0xbeefcafe
#define LOG_LEVEL		KERN_ALERT

/* declarations of functions that are part of operation structures */

struct inode *my_ramfs_get_inode(struct mnt_idmap *idmap, struct super_block *sb, const struct inode *dir,
		int mode);
static int my_ramfs_mknod(struct mnt_idmap *idmap, struct inode *dir,
		struct dentry *dentry, umode_t mode, dev_t dev);
static int my_ramfs_create(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry,
		umode_t mode, bool excl);
static int my_ramfs_mkdir(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, umode_t mode);

/* TODO 2/4: define super_operations structure */
static const struct super_operations my_ramfs_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_drop_inode,
};

static const struct inode_operations my_ramfs_dir_inode_operations = {
	/* TODO 5/8: Fill dir inode operations structure. */
	.create         = my_ramfs_create,
	.lookup         = simple_lookup,
	.link           = simple_link,
	.unlink         = simple_unlink,
	.mkdir          = my_ramfs_mkdir,
	.rmdir          = simple_rmdir,
	.mknod          = my_ramfs_mknod,
	.rename         = simple_rename,
};

static const struct file_operations my_ramfs_file_operations = {
	/* TODO 6/4: Fill file operations structure. */
	.read_iter      = generic_file_read_iter,
	.write_iter     = generic_file_write_iter,
	.mmap           = generic_file_mmap,
	.llseek         = generic_file_llseek,
};

static const struct inode_operations my_ramfs_file_inode_operations = {
	/* TODO 6/1: Fill file inode operations structure. */
	.getattr        = simple_getattr,
};

struct inode *my_ramfs_get_inode(struct mnt_idmap *idmap, struct super_block *sb, const struct inode *dir,
		int mode)
{
	struct inode *inode = new_inode(sb);

	if (!inode)
		return NULL;

	/* TODO 3/3: fill inode structure
	 *     - mode
	 *     - uid
	 *     - gid
	 *     - atime,ctime,mtime
	 *     - ino
	 */
	inode_init_owner(idmap, inode, dir, mode);
    inode_set_atime_to_ts(inode, current_time(inode));
    inode_set_mtime_to_ts(inode, current_time(inode));
    inode_set_ctime_to_ts(inode, current_time(inode));

	/* TODO 5/1: Init i_ino using get_next_ino */
	inode->i_ino = get_next_ino();

	/* TODO 6/1: Initialize address space operations. */
	inode->i_mapping->a_ops = &ram_aops;

	if (S_ISDIR(mode)) {
		/* TODO 3/2: set inode operations for dir inodes. */
		inode->i_op = &simple_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;

		/* TODO 5/1: use my_ramfs_dir_inode_operations for inode
		 * operations (i_op).
		 */
		inode->i_op = &my_ramfs_dir_inode_operations;

		/* TODO 3/1: directory inodes start off with i_nlink == 2 (for "." entry).
		 * Directory link count should be incremented (use inc_nlink).
		 */
		inc_nlink(inode);
	}

	/* TODO 6/4: Set file inode and file operations for regular files
	 * (use the S_ISREG macro).
	 */
	if (S_ISREG(mode)) {
		inode->i_op = &my_ramfs_file_inode_operations;
		inode->i_fop = &my_ramfs_file_operations;
	}

	return inode;
}

/* TODO 5/33: Implement my_ramfs_mknod, my_ramfs_create, my_ramfs_mkdir. */
static int my_ramfs_mknod(struct mnt_idmap *idmap, struct inode *dir,
		struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct inode *inode = my_ramfs_get_inode(idmap, dir->i_sb, dir, mode);

	if (inode == NULL)
		return -ENOSPC;

	d_instantiate(dentry, inode);
	dget(dentry);
	inode_set_mtime_to_ts(dir, current_time(inode));
    inode_set_ctime_to_ts(dir, current_time(inode));

	return 0;
}

static int my_ramfs_create(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry,
		umode_t mode, bool excl)
{
	return my_ramfs_mknod(idmap, dir, dentry, mode | S_IFREG, 0);
}

static int my_ramfs_mkdir(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int ret;

	ret = my_ramfs_mknod(idmap, dir, dentry, mode | S_IFDIR, 0);
	if (ret != 0)
		return ret;

	inc_nlink(dir);

	return 0;
}

static int my_ramfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root_inode;
	struct dentry *root_dentry;

	/* TODO 2/5: fill super_block
	 *   - blocksize, blocksize_bits
	 *   - magic
	 *   - super operations
	 *   - maxbytes
	 */
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = my_ramfs_BLOCKSIZE;
	sb->s_blocksize_bits = my_ramfs_BLOCKSIZE_BITS;
	sb->s_magic = my_ramfs_MAGIC;
	sb->s_op = &my_ramfs_ops;

	/* mode = directory & access rights (755) */
	root_inode = my_ramfs_get_inode(&nop_mnt_idmap, sb, NULL,
			S_IFDIR | S_IRWXU | S_IRGRP |
			S_IXGRP | S_IROTH | S_IXOTH);

	printk(LOG_LEVEL "root inode has %d link(s)\n", root_inode->i_nlink);

	if (!root_inode)
		return -ENOMEM;

	root_dentry = d_make_root(root_inode);
	if (!root_dentry)
		goto out_no_root;
	sb->s_root = root_dentry;

	return 0;

out_no_root:
	iput(root_inode);
	return -ENOMEM;
}

static struct dentry *my_ramfs_mount(struct file_system_type *fs_type,
		int flags, const char *dev_name, void *data)
{
	/* TODO 1/1: call superblock mount function */
	return mount_nodev(fs_type, flags, data, my_ramfs_fill_super);
}

/* TODO 1/6: define file_system_type structure */
static struct file_system_type my_ramfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "my_ramfs",
	.mount		= my_ramfs_mount,
	.kill_sb	= kill_litter_super,
};

static int __init my_ramfs_init(void)
{
	int err;

	/* TODO 1/1: register */
	err = register_filesystem(&my_ramfs_fs_type);
	if (err) {
		printk(LOG_LEVEL "register_filesystem failed\n");
		return err;
	}

	return 0;
}

static void __exit my_ramfs_exit(void)
{
	/* TODO 1/1: unregister */
	unregister_filesystem(&my_ramfs_fs_type);
}

module_init(my_ramfs_init);
module_exit(my_ramfs_exit);
