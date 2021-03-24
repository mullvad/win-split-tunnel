#pragma once

#include <filesystem>
#include <string>
#include <libcommon/string.h>

using common::string::KeyValuePairs;

class Settings
{
public:

	Settings(KeyValuePairs values)
		: m_values(std::move(values))
	{
	}

	static Settings FromFile(const std::filesystem::path &filename);

	const std::wstring &get(const std::wstring &key);

private:

	KeyValuePairs m_values;
};
