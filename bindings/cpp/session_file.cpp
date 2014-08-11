#include "elliptics/session.hpp"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

namespace ioremap { namespace elliptics {

class file_descriptor
{
public:
	file_descriptor(int fd) : m_fd(fd)
	{
	}

	~file_descriptor()
	{
		if (m_fd >= 0)
			close(m_fd);
	}

	int fd() const
	{
		return m_fd;
	}

private:
	int m_fd;
};

void session::read_file(const key &id, const std::string &file, uint64_t offset, uint64_t size)
{
	transform(id);

	session sess = clone();
	sess.set_exceptions_policy(throw_at_get);

	read_result_entry result = sess.read_data(id, offset, size).get_one();
	dnet_io_attr *io = result.io_attribute();

	int err;

	file_descriptor fd(open(file.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644));
	if (fd.fd() < 0) {
		err = -errno;
		throw_error(err, id, "Failed to open read completion file: '%s'", file.c_str());
	}

	err = pwrite(fd.fd(), result.file().data(), result.file().size(), offset);
	if (err <= 0) {
		err = -errno;
		throw_error(err, id, "Failed to write data into completion file: '%s'", file.c_str());
	}

	BH_LOG(get_logger(), DNET_LOG_NOTICE, "%s: read completed: file: '%s', offset: %llu, size: %llu, status: %d.",
			dnet_dump_id(&id.id()), file, offset, uint64_t(io->size), int(result.command()->status));
}

void session::write_file(const key &id, const std::string &file, uint64_t local_offset,
				uint64_t offset, uint64_t size)
{
	transform(id);

	session sess = clone();
	sess.set_exceptions_policy(throw_at_wait);

	int err;

	file_descriptor fd(open(file.c_str(), O_RDONLY | O_LARGEFILE | O_CLOEXEC));
	if (fd.fd() < 0) {
		err = -errno;
		throw_error(err, id, "Failed to open read completion file '%s'", file.c_str());
	}

	struct stat stat;
	memset(&stat, 0, sizeof(stat));

	err = fstat(fd.fd(), &stat);
	if (err) {
		err = -errno;
		throw_error(err, id, "Failed to stat to be written file '%s'", file.c_str());
	}

	if (local_offset >= (uint64_t)stat.st_size) {
		BH_LOG(get_logger(), DNET_LOG_NOTICE, "%s: File is already uploaded: '%s'",
				dnet_dump_id(&id.id()), file);
		return;
	}

	if (!size || size + local_offset >= (uint64_t)stat.st_size)
		size = stat.st_size - local_offset;

	dnet_io_control ctl;
	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.data = NULL;
	ctl.fd = fd.fd();
	ctl.local_offset = local_offset;

	memcpy(ctl.io.id, id.id().id, DNET_ID_SIZE);
	memcpy(ctl.io.parent, id.id().id, DNET_ID_SIZE);

	ctl.io.size = size;
	ctl.io.offset = offset;
	ctl.io.timestamp.tsec = stat.st_mtime;
	ctl.io.timestamp.tnsec = 0;
	ctl.id = id.id();

	write_data(ctl).wait();
}

}} // namespace ioremap::elliptics
