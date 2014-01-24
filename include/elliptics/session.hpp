/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
 * 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */

#ifndef ELLIPTICS_SESSION_HPP
#define ELLIPTICS_SESSION_HPP

#include <functional>
#include <vector>
#include <list>

#include "result_entry.hpp"
#include "packet.h"
#include "interface.h"

namespace ioremap { namespace elliptics {

class callback_result_entry;

typedef std::function<bool (const callback_result_entry &)> result_filter;
typedef std::function<bool (const std::vector<dnet_cmd> &, size_t)> result_checker;
typedef std::function<void (const error_info &, const std::vector<dnet_cmd> &)> result_error_handler;

namespace filters
{
bool positive(const callback_result_entry &entry);
bool negative(const callback_result_entry &entry);
bool all(const callback_result_entry &entry);
bool all_with_ack(const callback_result_entry &entry);
}

namespace checkers
{
bool no_check(const std::vector<dnet_cmd> &statuses, size_t total);
bool at_least_one(const std::vector<dnet_cmd> &statuses, size_t total);
bool all(const std::vector<dnet_cmd> &statuses, size_t total);
bool quorum(const std::vector<dnet_cmd> &statuses, size_t total);
}

class session;

namespace error_handlers
{
void none(const error_info &error, const std::vector<dnet_cmd> &statuses);

/*!
 * This handler allows to remove couple of replicas in case of bad writing
 *
 * If you write to 3 groups and at least 2 succesfull writings are mandotary and
 * in case of fail all succesffully written entries must be removed the
 * following code may be used:
 *
 * ```cpp
 * session sess(...);
 * session.set_checker(ioremap::elliptics::checkers::quorum);
 * session.set_error_handler(ioremap::elliptics::error_handlers::remove_on_fail(session));
 * ...
 * ```
 */
result_error_handler remove_on_fail(const session &sess);
}

class transport_control
{
	public:
		transport_control();
		transport_control(const struct dnet_id &id, unsigned int cmd, uint64_t cflags = 0);

		void set_key(const struct dnet_id &id);
		void set_command(unsigned int cmd);
		void set_cflags(uint64_t cflags);
		void set_data(void *data, unsigned int size);

		struct dnet_trans_control get_native() const;

	private:
		struct dnet_trans_control m_data;
};

struct address
{
	address(const std::string &l_host, const int l_port, const int l_family = AF_INET)
		: host(l_host), port(l_port), family(l_family) {}

	std::string		host;
	int			port;
	int			family;
};

class logger_interface
{
	public:
		virtual ~logger_interface() {}

		virtual void log(const int level, const char *msg) = 0;
};

class logger_data;

class logger
{
	public:
		explicit logger(logger_interface *interface, const int level = DNET_LOG_INFO);
		logger();
		logger(const logger &other);
		~logger();

		logger &operator =(const logger &other);

		void 		log(const int level, const char *msg);
		void 		print(int level, const char *format, ...) __attribute__ ((format(printf, 3, 4)));
		int			get_log_level();
		struct dnet_log		*get_native();

	protected:
		std::shared_ptr<logger_data> m_data;
};

class file_logger : public logger
{
	public:
		explicit file_logger(const char *file, const int level = DNET_LOG_INFO);
		~file_logger();
};

class node_data;
class session_data;

class node
{
	public:
		node();
		explicit node(const std::shared_ptr<node_data> &data);
		explicit node(const logger &l);
		node(const logger &l, struct dnet_config &cfg);
		node(const node &other);
		~node();

		node &operator =(const node &other);

		void			add_remote(const char *addr, const int port, const int family = AF_INET);
		void			add_remote(const char *addr);

		void			set_timeouts(const int wait_timeout, const int check_timeout);

		bool is_valid() const;

		logger get_log() const;
		struct dnet_node *	get_native();
		struct dnet_node *	get_native() const;

	protected:
		std::shared_ptr<node_data> m_data;

		friend class session;
		friend class session_data;
};

class key
{
	public:
		key();
		key(const std::string &remote);
		key(const dnet_id &id);
		key(const dnet_raw_id &id);
		key(const key &other);
		key &operator = (const key &other);
		~key();

		bool operator==(const key &other) const;
		bool operator <(const key &other) const;

		bool by_id() const;
		const std::string &remote() const;
		const dnet_id &id() const;
		const dnet_raw_id &raw_id() const;
		std::string to_string() const;

		void set_id(const dnet_id &id);
		void set_id(const dnet_raw_id &id);
		void set_group_id(uint32_t group);

		void transform(const session &sess);

		void set_trace_id(uint32_t trace_id) { m_trace_id = trace_id; }
		uint32_t get_trace_id() { return m_trace_id; }

	private:
		bool m_by_id;
		std::string m_remote;
		int m_reserved;
		struct dnet_id m_id;
		uint32_t m_trace_id;
};

class session
{
	public:
		enum exceptions_policy {
			no_exceptions		= 0x00, //! Exceptions are not thrown at any case
			throw_at_start		= 0x01, //! Exceptions can be thrown at method invoke
			throw_at_wait		= 0x02, //! Exceptions can be thrown at async_result::wait
			throw_at_get		= 0x04, //! Exceptions can be thrown at async_result::get
			throw_at_iterator_end	= 0x08, //! Exceptions can be thrown at any async_result::iterator action
			default_exceptions	= throw_at_wait | throw_at_get | throw_at_iterator_end
		};

		explicit session(const node &n);
		explicit session(const std::shared_ptr<session_data> &d);
		session(const session &other);
		virtual ~session();

		session clone() const;

		session &operator =(const session &other);

		/*!
		 * Converts string \a data to dnet_id \a id.
		 */
		void			transform(const std::string &data, struct dnet_id &id) const;
		/*!
		 * Converts string \a data to dnet_raw_id \a id.
		 */
		void			transform(const std::string &data, struct dnet_raw_id &id) const;
		/*!
		 * \overload transform()
		 */
		void			transform(const data_pointer &data, struct dnet_id &id) const;
		/*!
		 * Makes dnet_id be accessible by key::id() in the key \a id.
		 */
		void			transform(const key &id) const;

		/*!
		 * Sets \a groups to the session.
		 */
		void			set_groups(const std::vector<int> &groups);
		/*!
		 * Gets groups of the session.
		 */
		std::vector<int>	get_groups() const;

		/*!
		 * Filter all receiving entries by \a filter.
		 *
		 * Default value is filters::positive.
		 */
		void			set_filter(const result_filter &filter);
		/*!
		 * Returns filter.
		 */
		result_filter		get_filter() const;

		/*!
		 * Check success of operation by \a checker.
		 *
		 * Default value is checkers::at_least_one.
		 */
		void			set_checker(const result_checker &checker);
		/*!
		 * Returns checker.
		 */
		result_checker		get_checker() const;

		void			set_error_handler(const result_error_handler &error_handler);
		result_error_handler	get_error_handler() const;

		/*!
		 * Set exception policy \a policies.
		 *
		 * Default value is throw_at_wait | throw_at_get | throw_at_iterator_end.
		 */
		void			set_exceptions_policy(uint32_t policy);
		/*!
		 * Returns exception policy.
		 */
		uint32_t		get_exceptions_policy() const;

		/*!
		 * Sets command flags \a cflags to the session.
		 */
		void			set_cflags(uint64_t cflags);

		/*!
		 * Sets namespace to \a ns, this mangles all keys that written
		 * in this session so they won't collide with same key in any
		 * other namespace.
		 */
		void			set_namespace(const char *ns, int nsize);

		/*!
		 * Get id that this session was stuck to.
		 */
		dnet_id			get_direct_id();

		/*!
		 * Stick session to particular remote address.
		 */
		void			set_direct_id(dnet_addr remote_addr);
		void			set_direct_id(const char *saddr, int port, int family);

		/*!
		 * Gets command flags of the session.
		 */
		uint64_t		get_cflags() const;

		/*!
		 * Sets i/o flags \a ioflags to the session.
		 */
		void			set_ioflags(uint32_t ioflags);
		/*!
		 * Gets i/o flags of the session.
		 */
		uint32_t		get_ioflags() const;

		/*!
		 * Sets user flags \a user_flags to the session.
		 */
		void			set_user_flags(uint64_t user_flags);

		/*!
		 * Sets timestamp for given session.
		 * All write operations will use this timestamp, instead of system time.
		 * If set to zero (default), system time will be used.
		 */
		void			set_timestamp(struct dnet_time *ts);
		void			get_timestamp(struct dnet_time *ts);

		/*!
		 * Gets user flags of the session.
		 */
		uint64_t		get_user_flags() const;

		/*!
		 * Set/get transaction timeout
		 */
		void			set_timeout(unsigned int timeout);
		long			get_timeout() const;

		/*!
		 * Sets/gets trace_id for all elliptics commands
		 */
		void			set_trace_id(uint32_t trace_id);
		uint32_t		get_trace_id();

		/*!
		 * Read file by key \a id to \a file by \a offset and \a size.
		 */
		void			read_file(const key &id, const std::string &file, uint64_t offset, uint64_t size);
		/*!
		 * Write file from \a file to server by key \a id, \a offset and \a size.
		 */
		void			write_file(const key &id, const std::string &file, uint64_t local_offset,
							uint64_t offset, uint64_t size);

		/*!
		 * Reads data from server by \a key id and dnet_io_attr \io.
		 * Data is requested iteratively to \a groups until the first success
		 * or groups are ended.
		 * Command is sent to server is DNET_CMD_READ.
		 *
		 * Returns async_read_result.
		 */
		async_read_result read_data(const key &id, const std::vector<int> &groups, const dnet_io_attr &io);
		/*!
		 * \overload read_data()
		 * Allows to specify the command \a cmd.
		 */
		async_read_result read_data(const key &id, const std::vector<int> &groups, const dnet_io_attr &io, unsigned int cmd);
		/*!
		 * \overload read_data()
		 * Allows to specify the single \a group.
		 */
		async_read_result read_data(const key &id, int group_id, const struct dnet_io_attr &io);
		/*!
		 * \overload read_data()
		 * Allows to specify the \a offset and the \a size.
		 */
		async_read_result read_data(const key &id, const std::vector<int> &groups, uint64_t offset, uint64_t size);
		/*!
		 * \overload read_data()
		 * Allows to specify the \a offset and the \a size.
		 * Groups are generated automatically by session::mix_states().
		 */
		async_read_result read_data(const key &id, uint64_t offset, uint64_t size);

		/*!
		 * Filters the list \a groups and leaves only ones with the latest
		 * data at key \a id.
		 *
		 *
		 * Returns sorted async_lookup_result.
		 */
		async_lookup_result prepare_latest(const key &id, const std::vector<int> &groups);

		/*!
		 * Reads the latest data from server by the key \a id, \a offset and \a size.
		 *
		 *
		 * Returns async_read_result.
		 */
		async_read_result read_latest(const key &id, uint64_t offset, uint64_t size);

		/*!
		 * Writes data to server by the dnet_io_control \a ctl.
		 *
		 * Returns async_write_result.
		 */
		async_write_result write_data(const dnet_io_control &ctl);

		/*!
		 * Writes data \a file to server by the dnet_io_attr \a io and
		 *
		 * Returns async_write_result
		 */
		async_write_result write_data(const dnet_io_attr& io, const data_pointer &file);
		/*!
		 * Writes data \a file by the key \a id and remote offset \a remote_offset.
		 *
		 * Returns async_write_result.
		 *
		 * \note Calling this method is equal to consecutive calling
		 * of write_prepare(), write_plain() and write_commit().
		 */
		async_write_result write_data(const key &id, const data_pointer &file, uint64_t remote_offset);

		/*!
		 * Writes data \a file by the key \a id and remote offset \a remote_offset chunk by chunk with a size \chunk_size.
		 *
		 * Returns async_write_result.
		 *
		 * \note Calling this method is equal to consecutive calling
		 * of write_prepare(), write_plain() and write_commit().
		 */
		async_write_result write_data(const key &id, const data_pointer &file, uint64_t remote_offset, uint64_t chunk_size);


		/*!
		 * Reads data by \a id and passes it through \a converter. If converter returns the same data
		 * it's threated as data is already up-to-date, othwerwise low-level write-cas with proper
		 * checksum and \a remote_offset is invoked.
		 *
		 * If server returns -EBADFD data is read and processed again.
		 * The whole process iterates not more than \a count times.
		 *
		 * Returns async_write_result.
		 */
		async_write_result write_cas(const key &id, const std::function<data_pointer (const data_pointer &)> &converter,
				uint64_t remote_offset, int count = 10);

		/*!
		 * Writes data \a file by the key \a id and remote offset \a remote_offset.
		 *
		 * Writing is refused if check sum of server data is not equal
		 * to \a old_csum. elliptics::error with -EBADFD is thrown at this case.
		 *
		 * Returns async_write_result.
		 */
		async_write_result write_cas(const key &id, const data_pointer &file, const struct dnet_id &old_csum, uint64_t remote_offset);

		/*!
		 * Prepares \a psize bytes place to write data by \a id and writes data by \a file and by \a remote_offset
		 *
		 * Returns async_write_result.
		 *
		 * \note Server marks the object by \a id as incomplete and inaccessible until write_commit is called.
		 *       psize is amount of bytes which server should prepare for future object.
		 *       If you about to write data by offset, then psize should defines final size of full object
		 *       rather then expecting that server reserves psize bytes after remote_offset of current object.
		 */
		async_write_result write_prepare(const key &id, const data_pointer &file, uint64_t remote_offset, uint64_t psize);

		/*!
		 * Writes data \a file by the key \a id and remote offset \a remote_offset in prepared place.
		 *
		 * Returns async_write_result.
		 *
		 * \note Server writes data by offset in prepared place and
		 *       remains \a id as incomplete and inaccessible until write_commit is called.
		 *       While write_plain data shouldn't go out of prepared place.
		 */
		async_write_result write_plain(const key &id, const data_pointer &file, uint64_t remote_offset);

		/*!
		 * Writes data \a file by the key \a id and remote offset \a remote_offset and commit key \a id data by \a csize.
		 *
		 * Returns async_write_result.
		 *
		 * \note Server last writes data by offset in prepared place, commits all data and truncates it by csize.
		 *       After commit server marks the object by \a id as complete and it becomes accessible.
		 *       csize could be less then prepared place size. In this case object will be truncated by csize.
		 *       But csize shouldn't be more then size of prepared place.
		 */
		async_write_result write_commit(const key &id, const data_pointer &file, uint64_t remote_offset, uint64_t csize);

		/*!
		 * Writes data \a file by the key \a id and remote offset \a remote_offset.
		 * Also writes data to the server cache.
		 *
		 * Life-length of the object is set by \a timeout in seconds. If \a timeout is null
		 * object will live forever until the death of the server.
		 *
		 * Returns async_write_result.
		 */
		async_write_result write_cache(const key &id, const data_pointer &file, long timeout);

		/*!
		 * Returns address (ip and port pair) of remote node where
		 * data with key \a id may be in group \a group_id.
		 */
		std::string		lookup_address(const key &id, int group_id = 0);

		/*!
		 * Lookups information for key \a id.
		 *
		 * Returns async_lookup_result.
		 */
		async_lookup_result lookup(const key &id);

		/*!
		 * Removes all the entries of key \a id at server nodes.
		 *
		 * Returns async_remove_result.
		 */
		async_remove_result remove(const key &id);

		/*!
		 * Queries statistics information from the server nodes.
		 *
		 * Returns async_stat_result.
		 */
		async_stat_result stat_log();
		/*!
		 * \overload stat_log()
		 * Allows to specify the key \a id.
		 */
		async_stat_result stat_log(const key &id);

		/*!
		 * Queries statistics information from the server nodes.
		 *
		 * Returns async_stat_count_result.
		 */
		async_stat_count_result stat_log_count();

		/*!
		 * Returns the number of session states.
		 */
		int			state_num();

		/*!
		 * Requests execution of custom command at server.
		 *
		 * Returns async_genetic_result.
		 */
		async_generic_result request_cmd(const transport_control &ctl);

		/*!
		 * Changes node \a status on given \a address, \a port and network \a family.
		 */
		void			update_status(const char *addr, const int port,
						const int family, struct dnet_node_status *status);
		/*!
		 * Changes node \a status on key \a id.
		 */
		void			update_status(const key &id, struct dnet_node_status *status);

		/*!
		 * Reads data in range specified in \a io at group \a group_id.
		 *
		 * Returns async_read_result.
		 */
		async_read_result read_data_range(const struct dnet_io_attr &io, int group_id);

		/*!
		 * \internal
		 * \overload read_data_range()
		 * Synchronous overload.
		 *
		 * \note This method is left only for compatibility.
		 */
		std::vector<std::string> read_data_range_raw(struct dnet_io_attr &io, int group_id);

		/*!
		 * Removes data in range specified in \a io at group \a group_id.
		 *
		 * Returns async_read_result.
		 */
		async_read_result remove_data_range(const struct dnet_io_attr &io, int group_id);

		/*!
		 * Returns the list of network routes.
		 */
		std::vector<std::pair<struct dnet_id, struct dnet_addr> > get_routes();

		async_iterator_result start_iterator(const key &id, const std::vector<dnet_iterator_range>& ranges,
								uint32_t type, uint64_t flags,
								const dnet_time& time_begin = dnet_time(),
								const dnet_time& time_end = dnet_time());
		async_iterator_result pause_iterator(const key &id, uint64_t iterator_id);
		async_iterator_result continue_iterator(const key &id, uint64_t iterator_id);
		async_iterator_result cancel_iterator(const key &id, uint64_t iterator_id);

		/*!
		 * Starts execution for \a id of the given \a event with \a data.
		 *
		 * If \a id is null, event is sent to all groups specified in the session.
		 *
		 * Returns async_exec_result.
		 * Result contains all replies sent by nodes processing this event.
		 */
		async_exec_result exec(dnet_id *id, const std::string &event, const data_pointer &data);
		/*!
		 * Starts execution for \a id of the given \a event with \a data.
		 * \a src_key used as sub-id to snap execution to a distinct worker,
		 * execs with the same \a id and \a src_key will be processed by the same worker
		 * (subject to worker execution mode).
		 *
		 * If \a id is null, event is sent to all groups specified in the session.
		 *
		 * Returns async_exec_result.
		 * Result contains all replies sent by nodes processing this event.
		 */
		async_exec_result exec(dnet_id *id, int src_key, const std::string &event, const data_pointer &data);
		/*!
		 * Sends execution request of the given \a event and \a data
		 * to the party specified by a given \a context.
		 *
		 * Returns async_exec_result.
		 * Result contains all replies sent by nodes processing this event.
		 */
		async_exec_result exec(const exec_context &context, const std::string &event, const data_pointer &data);

		/*!
		 * Send an \a event with \a data to \a id continuing the process specified by \a context.
		 *
		 * If \a id is null event is sent to all groups specified in the session.
		 *
		 * Returns async_exec_result.
		 * Result contains only the information about starting of event procession, so there is no
		 * information if it was finally processed successfully.
		 */
		async_push_result push(dnet_id *id, const exec_context &context, const std::string &event, const data_pointer &data);
		/*!
		 * Reply \a data to initial starter of the process specified by \a context.
		 *
		 * If \a state is equal to exec_context::final it is the last reply, otherwise there will be more.
		 *
		 * Returns async_reply_result.
		 * Result contains information if starter received the reply.
		 */
		async_reply_result reply(const exec_context &context, const data_pointer &data, exec_context::final_state state);

		/*!
		 * Send reply back to blocked execution client
		 *
		 * \note Left only for compatibility reasons.
		 */
		void			reply(const struct sph &sph, const std::string &event,
						const std::string &data,
						const std::string &binary);

		/*!
		 * Reads all data from server nodes by the list \a ios.
		 * Exception is thrown if no entry is read successfully.
		 *
		 * Returns async_read_result.
		 */
		async_read_result bulk_read(const std::vector<struct dnet_io_attr> &ios);
		/*!
		 * \overload bulk_read()
		 *
		 * Allows to specify the list of string \a keys.
		 */
		async_read_result bulk_read(const std::vector<std::string> &keys);
		/*!
		 * \overload bulk_read()
		 *
		 * Allows to specify the list of key \a keys.
		 */
		async_read_result bulk_read(const std::vector<key> &keys);

		/*!
		 * Writes all data \a data to server nodes by the list \a ios.
		 * Exception is thrown if no entry is written successfully.
		 *
		 * Returns async_write_result.
		 */
		async_write_result bulk_write(const std::vector<dnet_io_attr> &ios, const std::vector<data_pointer> &data);
		/*!
		 * \overload bulk_read()
		 *
		 * Allows to pass list of std::string as \a data.
		 */
		async_write_result bulk_write(const std::vector<struct dnet_io_attr> &ios, const std::vector<std::string> &data);

		async_set_indexes_result set_indexes(const key &id, const std::vector<index_entry> &indexes);
		async_set_indexes_result set_indexes(const key &id, const std::vector<std::string> &indexes,
				const std::vector<data_pointer> &data);
		async_set_indexes_result update_indexes(const key &id, const std::vector<index_entry> &indexes);
		async_set_indexes_result update_indexes(const key &id, const std::vector<std::string> &indexes,
				const std::vector<data_pointer> &data);
		async_set_indexes_result remove_indexes(const key &id, const std::vector<dnet_raw_id> &indexes);
		async_set_indexes_result remove_indexes(const key &id, const std::vector<std::string> &indexes);
		async_set_indexes_result update_indexes_internal(const key &id, const std::vector<index_entry> &indexes);
		async_set_indexes_result update_indexes_internal(const key &id, const std::vector<std::string> &indexes,
				const std::vector<data_pointer> &data);
		async_set_indexes_result remove_indexes_internal(const key &id, const std::vector<dnet_raw_id> &indexes);
		async_set_indexes_result remove_indexes_internal(const key &id, const std::vector<std::string> &indexes);
		async_generic_result remove_index_internal(const dnet_raw_id &id);
		async_generic_result remove_index_internal(const std::string &id);
		async_generic_result remove_index(const dnet_raw_id &id, bool remove_data);
		async_generic_result remove_index(const std::string &id, bool remove_data);

		async_find_indexes_result find_all_indexes(const std::vector<dnet_raw_id> &indexes);
		async_find_indexes_result find_all_indexes(const std::vector<std::string> &indexes);
		async_find_indexes_result find_any_indexes(const std::vector<dnet_raw_id> &indexes);
		async_find_indexes_result find_any_indexes(const std::vector<std::string> &indexes);

		async_list_indexes_result list_indexes(const key &id);

		/*!
		 * Returns logger object.
		 */
		logger get_logger() const;
		/*!
		 * Returns reference to parent node.
		 */
		node	get_node() const;
		/*!
		 * Returns reference to parent node.
		 */
		dnet_node *get_native_node() const;
		/*!
		 * Returns pointer to dnet_session.
		 */
		struct dnet_session *	get_native();

	protected:
		std::shared_ptr<session_data>		m_data;

		async_exec_result request(dnet_id *id, const exec_context &context);
		async_iterator_result iterator(const key &id, const data_pointer& request);
		async_find_indexes_result find_indexes_internal(const std::vector<dnet_raw_id> &indexes, bool intersect);

		void			mix_states(const key &id, std::vector<int> &groups);
		void			mix_states(std::vector<int> &groups);
		std::vector<int>	mix_states(const key &id);
		std::vector<int>	mix_states();
};

}} /* namespace ioremap::elliptics */

#endif // ELLIPTICS_SESSION_HPP
