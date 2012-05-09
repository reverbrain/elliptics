#include <elliptics/srw/srw.hpp>

using namespace ioremap::srw;

int main(int argc, char *argv[])
{
	struct srw_init_ctl ctl;

	ctl.binary = (char *)"/home/zbr/awork/tmp/srw/src/srw_worker";
	ctl.log = (char *)"/tmp/test.log";
	ctl.pipe = (char *)"/tmp/test-pipe";
	ctl.init = (char *)"/opt/elliptics/history.2/python.init";
	ctl.config = NULL;
	ctl.type = SRW_TYPE_PYTHON;
	ctl.num = 1;

	pool p(&ctl);

	std::string binary = "binary data";
	std::string script = "from time import time, ctime\n"
		"__return_data = 'Current time is ' + ctime(time()) + '"
		"|received binary data: ' + __input_binary_data_tuple[0].decode('utf-8')";

	for (int i = 0; i < 128; ++i)
		std::cerr << p.process(script, binary);
}
