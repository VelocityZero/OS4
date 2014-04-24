/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusep4.c -o fusep4 `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif
#include <libgen.h>
#include <ctype.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <limits.h>
#include "log.h"
#include "params.h"
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>

#endif

static int p4_getattr(const char *fpath, struct stat *stbuf)
{
	int res;

	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_access(const char *fpath, int mask)
{
	int res;

	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_readlink(const char *fpath, char *buf, size_t size)
{
	int res;

	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int p4_readdir(const char *fpath, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int p4_mknod(const char *fpath, mode_t mode, dev_t rdev)
{
	int res;

	/* On Linux this could just be 'mknod(fpath, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_mkdir(const char *fpath, mode_t mode)
{
	int res;

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_unlink(const char *fpath)
{
	int res;

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_rmdir(const char *fpath)
{
	int res;

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_chmod(const char *fpath, mode_t mode)
{
	int res;

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_chown(const char *fpath, uid_t uid, gid_t gid)
{
	int res;

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_truncate(const char *fpath, off_t size)
{
	int res;

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_utimens(const char *fpath, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_open(const char *fpath, struct fuse_file_info *fi)
{
	int res;

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int p4_read(const char *fpath, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	fd = open(fpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int p4_write(const char *fpath, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	fd = open(fpath, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int p4_statfs(const char *fpath, struct statvfs *stbuf)
{
	int res;

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_create(const char* fpath, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;

    int res;
    res = creat(fpath, mode);
    if(res == -1)
	return -errno;

    close(res);

    return 0;
}


static int p4_release(const char *fpath, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) fpath;
	(void) fi;
	return 0;
}

static int p4_fsync(const char *fpath, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) fpath;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int p4_setxattr(const char *fpath, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int p4_getxattr(const char *fpath, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int p4_listxattr(const char *fpath, char *list, size_t size)
{
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int p4_removexattr(const char *fpath, const char *name)
{
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations p4_oper = {
	.getattr	= p4_getattr,
	.access		= p4_access,
	.readlink	= p4_readlink,
	.readdir	= p4_readdir,
	.mknod		= p4_mknod,
	.mkdir		= p4_mkdir,
	.symlink	= p4_symlink,
	.unlink		= p4_unlink,
	.rmdir		= p4_rmdir,
	.rename		= p4_rename,
	.link		= p4_link,
	.chmod		= p4_chmod,
	.chown		= p4_chown,
	.truncate	= p4_truncate,
	.utimens	= p4_utimens,
	.open		= p4_open,
	.read		= p4_read,
	.write		= p4_write,
	.statfs		= p4_statfs,
	.create         = p4_create,
	.release	= p4_release,
	.fsync		= p4_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= p4_setxattr,
	.getxattr	= p4_getxattr,
	.listxattr	= p4_listxattr,
	.removexattr	= p4_removexattr,
#endif
};

void p4_usage()
{
    fprintf(stderr, "usage:  p4fs [FUSE and mount options] rootDir mountPoint\n");
    abort();
}

int main(int argc, char *argv[])
{
	umask(0);
	//mount--bind

  struct p4_state *p4_data;
  
  	if ((getuid() == 0) || (geteuid() == 0)) {
		fprintf(stderr, "Running p4FS as root opens unnacceptable security holes\n");
		return 1;
    }
  
    if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
		p4_usage();

    p4_data = malloc(sizeof(struct p4_state));
    
  	if (p4_data == NULL) {
		perror("main calloc");
		abort();
    }
  
  	p4_data->rootdir = realpath(argv[argc-2], NULL);
  	if (p4_data->rootdir == NULL)
  	{
		fprintf(stderr, "real path fail\n");
  		abort();
  	}
  	else{
  		printf("%s \n", p4_data->rootdir);
  	}
    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;
  
  
    p4_data->logfile = log_open();

  
  return fuse_main(argc, argv, &p4_oper, p4_data);
  
  
}














