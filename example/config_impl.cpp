#include "config.hpp"

#include <blackhole/repository/config/parser/rapidjson.hpp>

#include <rapidjson/document.h>
#include <rapidjson/filestream.h>

#include <fstream>

using namespace ioremap::elliptics::config;

config_parser::config_parser()
{
}

config_parser::~config_parser()
{
}

config config_parser::open(const std::string &path)
{
	FILE *f = fopen(path.c_str(), "r");
	if (!f) {
		int err = -errno;
		throw config_error() << "failed to open config file'" << path << "': " << strerror(-err);
	}

	rapidjson::FileStream stream(f);

	rapidjson::Document doc;
	doc.ParseStream<0>(stream);

	fclose(f);

	if (doc.HasParseError()) {
		std::ifstream in(path.c_str());
		if (in) {
			size_t offset = doc.GetErrorOffset();
			std::vector<char> buffer(offset);
			in.read(buffer.data(), offset);

			std::string data(buffer.begin(), buffer.end());
			std::string line;

			if (std::getline(in, line))
				data += line;

			/*
			 * Produce a pretty output about the error
			 * including the line and certain place where
			 * the error occured.
			 */

			size_t line_offset = data.find_last_of('\n');
			if (line_offset == std::string::npos)
				line_offset = 0;

			for (size_t i = line_offset; i < data.size(); ++i) {
				if (data[i] == '\t') {
					data.replace(i, 1, std::string(4, ' '));

					if (offset > i)
						offset += 3;
				}
			}

			const size_t line_number = std::count(data.begin(), data.end(), '\n') + 1;
			const size_t dash_count = line_offset < offset ? offset - line_offset - 1 : 0;

			throw config_error()
				<< "parser error at line " << line_number << ": " << doc.GetParseError() << std::endl
				<< data.substr(line_offset + 1) << std::endl
				<< std::string(dash_count, ' ') << '^' << std::endl
				<< std::string(dash_count, '~') << '+' << std::endl;
		}

		throw config_error() << "parser error: at unknown line: " << doc.GetParseError();
	}

	if (!doc.IsObject())
		throw config_error() << "root must be an object";

	auto root = blackhole::repository::config::transformer_t<rapidjson::Value>::transform(doc);
	return config("path", root);
}
