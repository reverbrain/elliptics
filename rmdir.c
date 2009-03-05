#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>

#define uloga(f, a...) fprintf(stderr, f, ##a)
#define ulog_err(f, a...) uloga(f ": %s [%d].\n", ##a, strerror(errno), errno)

//#define RMDIR_DEBUG

#ifdef RMDIR_DEBUG
#define ulog(f, a...) uloga(f, ##a)
#else
#define ulog(f, a...) do {} while (0)
#endif

static int do_rmdir(int dirfd, char *sub, int flags)
{
	int fd, err = 0;
	DIR *dir;
	struct dirent64 *d;

	if (flags != AT_REMOVEDIR)
		goto do_unlink;

	fd = openat(dirfd, sub, O_RDONLY);
	if (fd == -1) {
		ulog_err("Failed to open '%s' in %d", sub, dirfd);
		return -errno;
	}

	dir = fdopendir(fd);
	err = 0;

	while ((d = readdir64(dir)) != NULL) {
		if (d->d_name[0] == '.' && d->d_name[1] == '\0')
			continue;
		if (d->d_name[0] == '.' && d->d_name[1] == '.' && d->d_name[2] == '\0')
			continue;

		if (d->d_type == DT_DIR) {
			err = do_rmdir(fd, d->d_name, AT_REMOVEDIR);
			if (err)
				break;
		} else {
			err = unlinkat(fd, d->d_name, 0);
			if (err) {
				ulog_err("Failed to remove %s/%s", sub, d->d_name);
				break;
			}
		}
	}
	close(fd);
	
do_unlink:
	if (!err) {
		err = unlinkat(dirfd, sub, flags);
		if (err)
			ulog_err("Failed to remove %s", sub);
	}
	
	return err;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		uloga("Usage: %s <dir>\n", argv[0]);
		return -1;
	}

	return do_rmdir(-1, argv[1], AT_REMOVEDIR);
}
