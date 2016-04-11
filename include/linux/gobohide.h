#ifndef _LINUX_GOBOHIDE_H
#define _LINUX_GOBOHIDE_H

#include <linux/fs.h>
#include <linux/dcache.h>

/* Gobohide internal ioctls */

#define GOBOHIDE_HIDEINODE    0x0000001 /* Hide a given inode number */
#define GOBOHIDE_UNHIDEINODE  0x0000002 /* Unhide a given inode number */
#define GOBOHIDE_COUNTHIDDEN  0x0000003 /* Get the number of inodes hidden */
#define GOBOHIDE_GETHIDDEN    0x0000004 /* Get the inodes hidden */

struct hide {
   ino_t i_ino;            /* shortcut to inode number */
   struct file *filp;      /* used to recover the inode's pathname */
   struct path path;       /* stores the path after a call to user_lpath */
   char *pathname;         /* a fresh cache of the inode's pathname */
   unsigned long page;     /* page on which pathname has been copied to */
   unsigned long refcount; /* number of reference counts to this object */
   int unlinked;           /* has the structure been unlinked yet? */
   struct list_head head;  /* a simple doubly linked list */
};

struct gobohide_stats {
   int hidden_inodes;      /* how many inodes we're hiding */
   int filled_size;        /* how many inodes we filled in hidden_list */
   char **hidden_list;     /* the hidden list */
};

/* Structure provided by the user on the ioctl to hide or unhide an entry */
struct gobohide_user {
   char operation;               /* the operation to be performed */
   ino_t inode;                  /* the inode number */
   const char *pathname;         /* the pathname being submitted */
   char symlink;                 /* is inode a symlink? */
   struct gobohide_stats stats;  /* holds statistics */
};

#ifdef CONFIG_GOBOHIDE_FS

int  gobohide_fs_ioctl(struct inode *inode, unsigned long arg);
ino_t gobohide_translate_inode_nr(struct inode *inode);
struct hide *gobohide_get(ino_t ino, const char *filename,
	int namelen, struct dentry *parent);
int  gobohide_put(struct hide *entry);
int  gobohide_remove(struct hide *hide);

#else

#define gobohide_fs_ioctl(inode, arg) 0
#define ino_t gobohide_translate_inode_nr(inode) 0
#define gobohide_get(ino, filename, namelen, parent) NULL
#define gobohide_put(entry) 0
#define gobohide_remove(hide) 0

#endif  /* CONFIG_GOBOHIDE_FS */
#endif  /* _LINUX_GOBOHIDE_H */
