/*
 * Copyright (C) 2002-2011 GoboLinux.org
 *
 * These modifications are released under the GNU General Public License
 * version 2 or later, incorporated herein by reference.
 * Modifications/features/bug fixes based on or derived from this code
 * fall under the GPL and must retain the authorship, copyright and license
 * notice.  This file is not a complete program and may only be used when
 * the entire operating system is licensed under the GPL.
 *
 * See the file COPYING in this distribution for more information.
 *
 * Author: Felipe W Damasio <felipewd@gmail.com>.
 * Original idea: Lucas C. Villa Real <lucasvr@gobolinux.org>
 *
 * Changes:
 * 12-Sep-2011 - Lucas C. Villa Real
 *               Take the superblock into account when comparing the dentries
 *               in order to allow mount points to be hidden.
 *
 * 03-Sep-2011 - Lucas C. Villa Real
 *               Security updates. Thanks to Dan Rosenberg for his code review.
 *
 * 18-May-2007 - Lucas C. Villa Real
 *               Added support to unionfs.
 *
 * 04-Jul-2006 - Lucas C. Villa Real
 *               Added GoboHide support to all filesystems through the VFS.
 *
 * 21-Feb-2004 - Lucas C. Villa Real
 *               Added an extra check for the inode's VFS root, so that
 *               the same inode number on different partitions don't get
 *               hidden mistakenly.
 *
 * 11-Nov-2003 - Lucas C. Villa Real
 *               Removed the spinlocks from gobolinux_show_hidden(), since
 *               we were already working with list_for_each_safe(), which
 *               iterates safely against removal of list entries.
 *
 * 05-May-2003 - Felipe W Damasio
 *               Using read-write locks instead of spinlocks,
 *               improving quite a bit read operations
 *               (allow concurrent readers, but only a single writer)
 *
 * 28-Apr-2003 - Lucas C. Villa Real
 *               Centralized checks for UID on gobolinux/fs/ioctl.c.
 *               Fixed get_free_page() to work on 64-bit archs as well.
 *
 * 12-Apr-2003 - Lucas C. Villa Real
 *               Removed support for UID's different than 0 hide inodes.
 *
 * 24-Mar-2003 - Lucas C. Villa Real
 *               Modified struct hide and calls so we have pathnames related
 *               to the "real" root dir and not the the mount point.
 *
 * 17-Mar-2003 - Lucas C. Villa Real
 *               Added support for full pathname, rather than dealing only
 *               with inode numbers.
 *
 * 10-Jan-2003 - Lucas C. Villa Real
 *               Added statistics.
 */
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/gobohide.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/mount.h>
#include <linux/path.h>
#include "mount.h"

#ifdef CONFIG_UNION_FS
#include "unionfs/union.h"
#endif

#include <asm/uaccess.h>

#define GOBOHIDE_INODE_EQUALS(p,i) ((p)->dentry->d_inode->i_ino == i)

static LIST_HEAD(gobohide_inode_list);
static int gobohide_inode_list_size = 0;
static DEFINE_RWLOCK(gobohide_inode_rwlock);

static int gobohide_resolve_path(struct hide *entry);
static int gobohide_remove_unlocked(struct hide *entry, int remove);
static int gobohide_inode_add(ino_t ino, const char *pathname);
static int gobohide_inode_del(ino_t ino, const char *pathname);
static int gobohide_count_hidden(struct gobohide_user __user *uhide);
static int gobohide_get_hidden(int count, struct gobohide_user __user *uhide);
static struct hide *gobohide_get_unlocked(ino_t i_ino, const char *filename,
	int namelen, struct dentry *parent);

/**
 * gobohide_fs_ioctl - Handle fs-related ioctls
 * @inode: inode number being added/removed from the hide-list
 * @hide: structure containing the user's request
 */
int gobohide_fs_ioctl(struct inode *inode, unsigned long arg)
{
	struct gobohide_user __user *uhide = (struct gobohide_user __user *) arg;
	struct gobohide_user hide;
	struct user_namespace *ns = current_user_ns();
	const struct cred *cred = current_cred();
	kuid_t root_uid = make_kuid(ns, 0);
	int error = 0;

	if (copy_from_user(&hide, uhide, sizeof(struct gobohide_user)))
		return -EFAULT;

	/* We only support symbolic links and directories */
	if (hide.inode && !S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
		return -EINVAL;

	/* We only allow process with admin privileges
	 * to use the fs-related gobo ioctls
	 */
	if (!uid_eq(cred->uid, root_uid) && !uid_eq(cred->euid, root_uid))
		return -EPERM;

	switch (hide.operation) {
		case GOBOHIDE_HIDEINODE:
			error = gobohide_inode_add(hide.inode, hide.pathname);
			break;
		case GOBOHIDE_UNHIDEINODE:
			error = gobohide_inode_del(hide.inode, hide.pathname);
			break;
		case GOBOHIDE_COUNTHIDDEN:
			error = gobohide_count_hidden(uhide);
			break;
		case GOBOHIDE_GETHIDDEN:
			error = gobohide_get_hidden(hide.stats.hidden_inodes, uhide);
			break;
		default:
			return -EOPNOTSUPP;
	}

	return error;
}

/**
 * gobohide_resolve_path - Resolves the pathname of a given dentry
 * @entry: structure holding the dentry structure and the destination buffer.
 *
 * After the structure has been used, its member 'page' must be returned with
 * a call to free_page().
 */
static int gobohide_resolve_path(struct hide *entry)
{
	int len, ret;
	struct file *filp = entry->filp;
	struct path path = { .mnt = filp->f_path.mnt, .dentry = filp->f_path.dentry };

	entry->page = __get_free_page(GFP_USER);
	if (! entry->page)
		return -ENOMEM;

	entry->pathname = d_path(&path, (char *) entry->page, PAGE_SIZE);
	if (IS_ERR(entry->pathname)) {
		ret = PTR_ERR(entry->pathname);
		entry->pathname = NULL;
		free_page(entry->page);
		entry->page = 0;
		return ret;
	}

	len = PAGE_SIZE + entry->page - (unsigned long) entry->pathname;
	return len < PATH_MAX ? len : PATH_MAX;
}

/**
 * gobohide_count_hidden - Counts how many inodes are hidden.
 * @hide: the structure containing a pointer to store the number of inodes
 *        hidden.
 */
static int gobohide_count_hidden(struct gobohide_user __user *uhide)
{
	struct gobohide_stats __user *stats = &uhide->stats;
	unsigned long flags;
	int num, ret;

	read_lock_irqsave(&gobohide_inode_rwlock, flags);
	num = gobohide_inode_list_size;
	read_unlock_irqrestore(&gobohide_inode_rwlock, flags);

	ret = put_user(num, &stats->hidden_inodes);
	if (ret)
		return -EFAULT;

	return 0;
}

/**
 * gobohide_get_hidden - Get the currently hidden inodes. The uhide structure
 *        has been already verified and validated by the caller, so we're safe
 *        to invoke copy_to_user to members of that structure.
 *
 * @count: maximum number of entries to copy to the user-provided buffer.
 * @hide: the structure containing a pointer to a previous-allocated array
 *        of no more than @hide->stats.hidden_inodes elements of unsigned long.
 *
 * This array is filled with the directories being hidden.
 */
static int gobohide_get_hidden(int count, struct gobohide_user __user *uhide)
{
	struct gobohide_stats __user *stats = &uhide->stats;
	struct hide *entry, *next, **array;
	int i, copied_entries = 0, ret = 0;
	unsigned long flags;
	size_t len;

	array = kmalloc(sizeof(struct hide *) * count, GFP_KERNEL);
	if (! array)
		return -ENOMEM;

	/* Since copy_to_user may sleep data can't be copied with the lock held */
	write_lock_irqsave(&gobohide_inode_rwlock, flags);
	if (gobohide_inode_list_size) {
		list_for_each_entry_safe(entry, next, &gobohide_inode_list, head) {
			if (entry && (copied_entries < count)) {
				/* Don't let the entry go away */
				entry->refcount++;
				array[copied_entries++] = entry;
			} else
				break;
		}
	}
	write_unlock_irqrestore(&gobohide_inode_rwlock, flags);

	/* Write the list of entries to user memory */
	for (i=0; i<copied_entries; ++i) {
		entry = array[i];
		len = strlen(entry->pathname);
		if (ret == 0 && copy_to_user(stats->hidden_list[i],
			entry->pathname,len)) {
			/* Don't break out so that all entries are put() back */
			ret = -EFAULT;
		}
		gobohide_put(entry);
	}

	/* Update filled_size with the number of entries which were copied */
	if (ret == 0 && put_user(copied_entries, &stats->filled_size))
		ret = -EFAULT;

	kfree(array);
	return ret;
}

ino_t gobohide_translate_inode_nr(struct inode *inode)
{
	ino_t ino = inode->i_ino;
#ifdef CONFIG_UNION_FS
	if (inode->i_sb->s_op == &unionfs_sops) {
		/* we must take the inode number from the underlying filesystem */
		struct inode *lower_inode = unionfs_lower_inode(inode);
		ino = lower_inode ? lower_inode->i_ino : inode->i_ino;
	}
#endif
	return ino;
}

/**
 * gobohide_inode_add - Add the inode to the "must hide" list
 * @ino: inode to be added
 * @pathname: the pathname associated with @ino
 */
static int gobohide_inode_add(ino_t ino, const char *pathname)
{
	int len, ret;
	struct path *path;
	struct hide *entry, *old;
	struct dentry *dentry;
	unsigned long flags;

	entry = kmalloc(sizeof(struct hide), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->refcount = 1;
	entry->unlinked = 0;

	path = &entry->path;
	ret = user_lpath(pathname, path);
	if (ret)
		goto out_free;
	else if (! GOBOHIDE_INODE_EQUALS(path, ino)) {
		ret = -ENOENT;
		goto out_path_put;
	}

	entry->filp = dentry_open(path, O_NOFOLLOW|O_PATH, current_cred());
	if (IS_ERR(entry->filp)) {
		ret = PTR_ERR(entry->filp);
		goto out_path_put;
	}

	len = gobohide_resolve_path(entry);
	if (len < 0) {
		ret = len;
		goto out_fput;
	}

	dentry = entry->filp->f_path.dentry;
	if (! dentry) {
		ret = -ENOENT;
		goto out_free_page;
	}

	/* Get updated inode number */
	entry->i_ino = gobohide_translate_inode_nr(dentry->d_inode);

	write_lock_irqsave(&gobohide_inode_rwlock, flags);
	old = gobohide_get_unlocked(entry->i_ino, dentry->d_name.name,
		dentry->d_name.len+1, dentry->d_parent);

	if (old) {
		write_unlock_irqrestore(&gobohide_inode_rwlock, flags);
		ret = -EEXIST;
		goto out_free_page;
	}

	gobohide_inode_list_size++;
	list_add(&entry->head, &gobohide_inode_list);
	write_unlock_irqrestore(&gobohide_inode_rwlock, flags);

	return 0;

out_free_page:
	free_page(entry->page);
out_fput:
	fput(entry->filp);
out_path_put:
	path_put(path);
out_free:
	kfree(entry);
	return ret;
}

/**
 * gobohide_inode_del - Remove the inode from the "must hide" list
 * @ino: inode to be removed
 */
static int gobohide_inode_del(ino_t ino, const char *pathname)
{
	int len, ret;
	struct path *path;
	unsigned long flags;
	struct hide n, *entry, *aux;

	path = &n.path;
	ret = user_lpath(pathname, path);
	if (ret)
		return ret;
	else if (! GOBOHIDE_INODE_EQUALS(path, ino)) {
		ret = -ENOENT;
		goto out_path_put;
	}

	n.filp = dentry_open(path, O_NOFOLLOW|O_PATH, current_cred());
	if (IS_ERR(n.filp)) {
		ret = PTR_ERR(n.filp);
		goto out_path_put;
	}

	len = gobohide_resolve_path(&n);
	if (len < 0) {
		ret = len;
		goto out_fput;
	}

	/* Get updated inode number */
	ino = gobohide_translate_inode_nr(n.filp->f_path.dentry->d_inode);

	write_lock_irqsave(&gobohide_inode_rwlock, flags);
	if (gobohide_inode_list_size) {
		list_for_each_entry_safe(entry, aux, &gobohide_inode_list, head) {
			struct file *filp = entry->filp;
			struct dentry *filp_dentry = filp->f_path.dentry;
			struct mount *mnt = real_mount(filp->f_path.mnt)->mnt_parent;
			struct dentry *mnt_dentry = mnt->mnt_mountpoint;
			ino_t mnt_ino = mnt_dentry->d_inode->i_ino;

			if ((entry->i_ino == ino && path->dentry->d_sb == filp_dentry->d_sb) ||
				(mnt_ino == ino && path->dentry->d_sb == mnt_dentry->d_sb)) {
				gobohide_remove_unlocked(entry, 1);
				break;
			}
		}
	}
	write_unlock_irqrestore(&gobohide_inode_rwlock, flags);

	free_page(n.page);
	ret = 0;

out_fput:
	fput(n.filp);
out_path_put:
	path_put(path);
	return ret;
}

/**
 * gobohide_remove - Effectively removes the inode from the inode_list.
 * @hide: struct hide to be removed
 */
int gobohide_remove(struct hide *entry)
{
	unsigned long flags;
	int ret;

	write_lock_irqsave(&gobohide_inode_rwlock, flags);
	ret = gobohide_remove_unlocked(entry, 1);
	write_unlock_irqrestore(&gobohide_inode_rwlock, flags);

	return ret;
}

static int gobohide_remove_unlocked(struct hide *entry, int remove)
{
	if (remove && ! entry->unlinked) {
		/* Remove from the linked list */
		entry->unlinked = true;
		list_del(&entry->head);
		gobohide_inode_list_size--;
	}
	if (--entry->refcount == 0) {
		free_page(entry->page);
		fput(entry->filp);
		path_put(&entry->path);
		kfree(entry);
	}
	return 0;
}

/**
 * gobohide_get - Get the struct hide associated to the given inode. The inode
 *  is verified to exist in the "must hide" list through the comparison of the
 *  inode number and the superblock.
 *
 * @ino: inode being readdir'd
 * @filename: inode's filename
 * @namelen: inodes's filename length in bytes
 * @parent: the parent dentry for the given inode.
 *
 * If the inode number is in the inode_list, returns a pointer to its entry
 * in the inode_list or NULL if it isn't there. The returned entry must be
 * released with gobohide_put().
 */
struct hide *gobohide_get(ino_t ino, const char *filename, int namelen,
	struct dentry *parent)
{
	unsigned long flags;
	struct hide *entry;

	write_lock_irqsave(&gobohide_inode_rwlock, flags);
	entry = gobohide_get_unlocked(ino, filename, namelen, parent);
	write_unlock_irqrestore(&gobohide_inode_rwlock, flags);

	return entry;
}

static struct hide *gobohide_get_unlocked(ino_t ino, const char *filename,
	int namelen, struct dentry *parent)
{
	struct hide *entry = NULL;

	if (! ino || ! gobohide_inode_list_size)
		return NULL;

	list_for_each_entry(entry, &gobohide_inode_list, head) {
		struct file *filp = entry->filp;
		struct dentry *filp_dentry = filp->f_path.dentry;
		struct mount *mnt = real_mount(filp->f_path.mnt);
		struct dentry *mnt_dentry = mnt->mnt_mountpoint;
		ino_t mnt_ino = mnt_dentry->d_inode->i_ino;

		if ((entry->i_ino == ino && parent->d_sb == filp_dentry->d_sb) || 
			(mnt_ino == ino && parent->d_sb == mnt_dentry->d_sb)) {
			/* Increment the reference count and return the object */
			entry->refcount++;
			return entry;
		}
	}

	return NULL;
}

/*
 * Return an entry obtained from the gobohide_inode_list with gobohide_get().
 * @param entry Entry obtained from gobohide_get().
 */
int gobohide_put(struct hide *entry)
{
	unsigned long flags;
	int ret = -EINVAL;

	if (entry) {
		write_lock_irqsave(&gobohide_inode_rwlock, flags);
		ret = gobohide_remove_unlocked(entry, 0);
		write_unlock_irqrestore(&gobohide_inode_rwlock, flags);
	}

	return ret;
}

EXPORT_SYMBOL(gobohide_get);
EXPORT_SYMBOL(gobohide_put);
EXPORT_SYMBOL(gobohide_remove);
EXPORT_SYMBOL(gobohide_fs_ioctl);
