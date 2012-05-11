#include <elliptics/srw/srw.hpp>

static void kill_all_fds(const char *log)
{
	int fd, null_fd;

	for (int i = 3; i < 1024; ++i) {
		close(i);
	}

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		fd = -errno;
		fprintf(stderr, "Can not open /dev/null: %d\n", fd);
		exit(fd);
	}

	null_fd = fd;

	dup2(fd, STDIN_FILENO);

	fd = open(log, O_RDWR | O_APPEND);
	if (fd < 0) {
		fd = null_fd;
	}

	dup2(fd, STDERR_FILENO);
	dup2(fd, STDOUT_FILENO);
}

static void worker_usage(char *arg)
{
	std::cerr << "Usage: " << arg << " <options>\n" <<
		" -i init-file             - shared library path to load worker code from\n" <<
		" -c config-file           - config file for appropriate worker type\n" <<
		" -l log-file              - log file for worker\n" <<
		" -p pipe-base             - pipe base for worker: it will write to @pipe-base.w2c and read from @pipe-base.c2w\n" <<
		" -h                       - this help\n";
	exit(-1);
}

int main(int argc, char *argv[])
{
	int ch, type = -1;
	std::string log("/dev/stdout"), pipe("/tmp/test-pipe"), init, conf;

	while ((ch = getopt(argc, argv, "c:i:l:p:h")) != -1) {
		switch (ch) {
			case 'c':
				conf.assign(optarg);
				break;
			case 'i':
				init.assign(optarg);
				break;
			case 'l':
				log.assign(optarg);
				break;
			case 'p':
				pipe.assign(optarg);
				break;
			case 'h':
			default:
				worker_usage(argv[0]);
		}
	}

	kill_all_fds(log.c_str());

	try {
		ioremap::srw::worker<ioremap::srw::shared> w(log, pipe, init, conf);
		w.process();
	} catch (const std::exception &e) {
		std::ofstream l(log.c_str(), std::ios::app);
		l << getpid() << ": worker exception: " << e.what() << std::endl;
	}

	return 0;
}
