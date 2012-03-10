#include <elliptics/srw.hpp>

int main(int argc, char *argv[])
{
	int ch, type = -1;
	std::string log("/dev/stdout"), pipe("/tmp/test-pipe"), init;

	while ((ch = getopt(argc, argv, "i:l:p:t:")) != -1) {
		switch (ch) {
			case 'i':
				init.assign(optarg);
				break;
			case 'l':
				log.assign(optarg);
				break;
			case 'p':
				pipe.assign(optarg);
				break;
			case 't':
				type = atoi(optarg);
				break;
			default:
				exit(-1);
		}
	}

	switch (type) {
		case SRW_TYPE_PYTHON: {
			ioremap::srw::worker<ioremap::srw::python> w(log, pipe, init);
			w.process();
			break;
		}
		default:
			exit(-1);
	}

	return 0;
}
