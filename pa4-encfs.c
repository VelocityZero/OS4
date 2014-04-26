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

#define XATTR_ENCRYPTED "true"
#define XATTR_DECRYPTED "false"
#define ENCRYPT 		 1
#define DECRYPT 		 0
#define PASSTHROUGH 	-1
#define XATTR_FLAGS "user.encrypted"


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <libgen.h>

#include <limits.h>
#include <stdlib.h>

#include "aes-crypt.h"

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

struct p4_state {
    FILE *logfile;
    char *key_phrase;
    char *rootdir;
};
#define P4_DATA ((struct p4_state *) fuse_get_context()->private_data)


static void prependPath(char fpath[PATH_MAX], const char *path)
{
	strcpy(fpath, P4_DATA->rootdir);
	strncat(fpath, path, PATH_MAX);
}

static int p4_getattr(const char *fpath, struct stat *stbuf)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;


	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_access(const char *fpath, int mask)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_readlink(const char *fpath, char *buf, size_t size)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int p4_readdir(const char *fpath, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	char path[PATH_MAX];
	prependPath(path,fpath);

	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(path);
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
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;

	/* On Linux this could just be 'mknod(fpath, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_mkdir(const char *fpath, mode_t mode)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_unlink(const char *fpath)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_rmdir(const char *fpath)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;

	res = rmdir(path);
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
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_chown(const char *fpath, uid_t uid, gid_t gid)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_truncate(const char *fpath, off_t size)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_utimens(const char *fpath, const struct timespec ts[2])
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(path, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_open(const char *fpath, struct fuse_file_info *fi)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int p4_read(const char *fpath, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	char path[PATH_MAX];
	prependPath(path,fpath);

	//int fd;
	int res;

	(void) fi;
	(void) offset;

	char *mtext;
	size_t msize;
	int action = PASSTHROUGH;
	char xattr_value[8];
	ssize_t xattr_len;

	FILE *inFile, *outFile;

	inFile = fopen(path, "r");
	if (inFile == NULL)
		return -errno;
	// open file from memory - The Heap
	outFile = open_memstream(&mtext, &msize);
	if (outFile == NULL)
		return -errno;

	xattr_len = getxattr(path, XATTR_FLAGS, xattr_value, 8);
	if (xattr_len != -1 && !memcmp(xattr_value, XATTR_ENCRYPTED, 4))
		action = DECRYPT;

	do_crypt(inFile, outFile, action, P4_DATA->key_phrase);
	fclose(inFile);

	fflush(outFile);
	fseek(outFile, offset, SEEK_SET);
	res = fread(buf, 1, size, outFile);

	/*fd = open(path, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);*/
	if (res == -1)
		res = -errno;

	//close(fd);
	fclose(outFile);
	return res;
}

static int p4_write(const char *fpath, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	char path[PATH_MAX];
	prependPath(path,fpath);

	//int fd;
	int res;

	(void) fi;

	char *mtext;
	size_t msize;
	int action = PASSTHROUGH;
	char xattr_value[8];
	ssize_t xattr_len;

	FILE * inFile, * outFile;
	
	inFile = fopen(path, "r");
	if (inFile == NULL)
		return -errno;
	// open file from memory - The Heap
	outFile = open_memstream(&mtext, &msize);
	if (outFile == NULL)
		return -errno;

	xattr_len = getxattr(path, XATTR_FLAGS, xattr_value, 8);
	if (xattr_len != -1 && !memcmp(xattr_value, XATTR_ENCRYPTED, 4))
		action = DECRYPT;

	do_crypt(inFile, outFile, action, P4_DATA->key_phrase);
	fclose(inFile);

	fseek(outFile, offset, SEEK_SET);
	res = fwrite(buf, 1, size, outFile);

	/*fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);*/
	if (res == -1)
		res = -errno;
	fflush(outFile);

	if(action == DECRYPT)
		action = ENCRYPT;

	inFile = fopen(path, "w");
	fseek(outFile, 0, SEEK_SET);
	do_crypt(outFile, inFile, action, P4_DATA->key_phrase);

	fclose(outFile);
	fclose(inFile);
	//close(fd);
	return res;
}

static int p4_statfs(const char *fpath, struct statvfs *stbuf)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int p4_create(const char* fpath, mode_t mode, struct fuse_file_info* fi) {

	char path[PATH_MAX];
	prependPath(path,fpath);
	char *mtext;
	size_t msize;

	(void) mode;
    (void) fi;

    FILE * inFile, * outFile;

    outFile = fopen(path, "w");
    if (outFile == NULL)
    	return -errno;

    // open file from memory - The Heap
	inFile = open_memstream(&mtext, &msize);
	if (inFile == NULL)
		return -errno;

	do_crypt(inFile, outFile, ENCRYPT, P4_DATA->key_phrase);
	fclose(inFile);

    if(setxattr(path, XATTR_FLAGS, XATTR_ENCRYPTED, 4, 0))
		return -errno;

    /*int res;
    res = creat(path, mode);
    if(res == -1)
		return -errno;

    close(res);*/

	fclose(outFile);

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
	char path[PATH_MAX];
	prependPath(path,fpath);

	int res = lsetxattr(path, name, value, size, flags);

	if (res == -1)
		return -errno;
	return 0;
}

static int p4_getxattr(const char *fpath, const char *name, char *value,
			size_t size)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int p4_listxattr(const char *fpath, char *list, size_t size)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int p4_removexattr(const char *fpath, const char *name)
{
	char path[PATH_MAX];
	prependPath(path,fpath);
	int res = lremovexattr(path, name);
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
	int fuse_stat;
	struct p4_state *p4_data;

	p4_data = malloc(sizeof(struct p4_state));

	if (p4_data == NULL) {
		perror("main calloc");
		abort();
	}

	p4_data->key_phrase = argv[argc-3];
	p4_data->rootdir = realpath(argv[argc-2], NULL);
	
	argv[argc-3] = argv[argc-1];
	argv[argc-2] = NULL;
    argv[argc-1] = NULL;
    argc-=2;

	if (p4_data->rootdir == NULL)
	{
		fprintf(stderr, "realpath fail\n");
		abort();
	}



	fuse_stat = fuse_main(argc, argv, &p4_oper, p4_data);
	return fuse_stat;
}