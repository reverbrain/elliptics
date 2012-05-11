#include <elliptics/srw/srw.hpp>

using namespace ioremap::srw;

int main(int argc, char *argv[])
{
	struct srw_init_ctl ctl;

	ctl.binary = (char *)"/home/zbr/awork/tmp/srw/src/srw_worker";
	ctl.log = (char *)"/tmp/test.log";
	ctl.pipe = (char *)"/tmp/test-pipe";
	ctl.config = (char *)"/opt/elliptics/history.2/python.init";
	ctl.init = (char *)"/home/zbr/awork/tmp/srw/src/libelliptics_python_worker.so";
	ctl.num = 1;

	pool p(&ctl);

	std::string binary = "binary data";
	std::string script = "from time import time, ctime\n"
		"__return_data = 'Current time is ' + ctime(time()) + '"
		"|received binary data: ' + __input_binary_data_tuple[0].decode('utf-8')";
	std::string event = "python/eventXXX";

	struct sph header;
	memset(&header, 0, sizeof(struct sph));

	header.data_size = script.size();
	header.binary_size = binary.size();
	header.flags = 0;
	header.event_size = event.size();
	header.key = 0;

	for (int i = 0; i < 128; ++i)
		std::cerr << p.process(header, (char *)(event + script + binary).data());
}
