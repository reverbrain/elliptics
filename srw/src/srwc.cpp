#include <iostream>

#include <elliptics/srw.hpp>
#include <elliptics/srwc.h>

struct srwc *srwc_init_python(char *bin_path, char *log_path, char *pipe_base, char *init_path, int num, void *priv)
{
	struct srwc *s = NULL;

	try {
		std::string bin(bin_path);
		std::string log(log_path);
		std::string pipe(pipe_base);
		std::string init(init_path);

		s = (struct srwc *)malloc(sizeof(struct srwc));
		if (!s)
			return NULL;

		s->handler = new ioremap::srw::pool(bin, log, pipe, init, SRW_TYPE_PYTHON, num);
		s->priv = priv;
	} catch (const std::exception &e) {
		free(s);
		return NULL;
	}

	return s;
}

void srwc_cleanup_python(struct srwc *s)
{
	ioremap::srw::pool *srw = (ioremap::srw::pool *)s->handler;
	delete srw;

	free(s);
}

int srwc_process(struct srwc *s, struct srwc_ctl *ctl)
{
	try {
		std::string bin((char *)ctl->binary, ctl->binary_size);
		std::string data(ctl->cmd, ctl->cmd_size);
		std::string res;

		ioremap::srw::pool *srw = (ioremap::srw::pool *)s->handler;
		res = srw->process(data, bin);

		ctl->result = (char *)malloc(res.size() + 1);
		if (!ctl->result)
			return -ENOMEM;

		memcpy(ctl->result, res.data(), res.size());
		ctl->result[res.size()] = '\0';
		ctl->res_size = res.size();

		return 0;
	} catch (...) {
		return -EINVAL;
	}
}

int srwc_drop(struct srwc *s, int pid) {
	try {
		ioremap::srw::pool *srw = (ioremap::srw::pool *)s->handler;
		srw->drop(pid);
		return 0;
	} catch (...) {
		return -EINVAL;
	}
}
