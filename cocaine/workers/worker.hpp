#ifndef ELLIPTICS_WORKER
#define ELLIPTICS_WORKER

#include <cocaine/framework/worker.hpp>
#include <cocaine/framework/application.hpp>
#include <elliptics/session.hpp>

namespace ioremap { namespace elliptics {

class application : public cocaine::framework::application<application>
{
	public:
		enum update_index_action {
			insert_data,
			remove_data
		};

		struct on_update_base :
			public cocaine::framework::handler<application>,
			public std::enable_shared_from_this<on_update_base>
		{
			on_update_base(std::shared_ptr<application> app)
				: cocaine::framework::handler<application>(app)
			{
			}

			void on_chunk(const char *chunk, size_t size);
			void on_error(int code, const std::string &message);
			void on_close();

			void update_indexes(const exec_context &context, const dnet_id &request_id, const std::vector<index_entry> &indexes);
		};

		struct on_update_final :
			public cocaine::framework::handler<application>,
			public std::enable_shared_from_this<on_update_final>
		{
			on_update_final(std::shared_ptr<application> app)
				: cocaine::framework::handler<application>(app)
			{
			}

			void on_chunk(const char *chunk, size_t size);
			void on_error(int code, const std::string &message);
			void on_close();

			void update_index(const exec_context &context, const dnet_id &request_id, const index_entry &index, update_index_action action);
			void on_write_finished(session sess, const exec_context &context, const error_info &error);
			template <update_index_action action>
			data_pointer convert_index_table(const dnet_id &request_id, const data_pointer &index_data, const data_pointer &data);

			data_pointer m_previous_data;
		};

		application(std::shared_ptr<cocaine::framework::service_manager_t> service_manager);

		void initialize();

		ioremap::elliptics::session create_session();

	private:
		std::shared_ptr<ioremap::elliptics::logger> m_logger;
		std::shared_ptr<ioremap::elliptics::node> m_node;
		std::vector<int> m_groups;
};

} } // namespace ioremap::elliptics

#endif // ELLIPTICS_WORKER
