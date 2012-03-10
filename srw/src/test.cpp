#include <elliptics/srw.hpp>

using namespace ioremap::srw;

int main(int argc, char *argv[])
{
	pool p("/home/zbr/awork/tmp/srw/src/srw_worker", "/tmp/test.log",
			"/tmp/test-pipe", "/opt/elliptics/history.2/python.init", SRW_TYPE_PYTHON, 1);

	std::string binary = "binary data";
	std::string script = "from time import time, ctime\n"
		"__return_data = 'Current time is ' + ctime(time()) + '"
		"|received binary data: ' + __input_binary_data_tuple[0].decode('utf-8')";

	for (int i = 0; i < 128; ++i)
		std::cerr << p.process(script, binary);
}
