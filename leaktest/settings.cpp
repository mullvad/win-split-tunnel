#include "settings.h"
#include <fstream>
#include <stdexcept>
#include <vector>

//static
Settings Settings::FromFile(const std::filesystem::path &filename)
{
	std::ifstream source(filename);

	if (!source.is_open())
	{
		throw std::runtime_error("Failed to open settings file");
	}

	std::vector<std::wstring> intermediate;

	for (std::string kvp; source >> kvp; intermediate.emplace_back(common::string::ToWide(kvp)));

	return Settings(std::move(common::string::SplitKeyValuePairs(intermediate)));
}

const std::wstring &Settings::get(const std::wstring &key)
{
	auto it = m_values.find(key);

	if (it == m_values.end())
	{
		throw std::runtime_error("Settings key not present in settings file");
	}

	return it->second;
}
