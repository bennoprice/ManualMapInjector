#include <fstream>
#include "binary_file.hpp"

namespace binary_file
{
	std::unique_ptr<std::vector<std::uint8_t>> read_file(std::wstring_view path)
	{
		std::ifstream file(path.data(), std::ios::in | std::ios::binary | std::ios::ate);
		if (!file.is_open())
			return nullptr;

		auto size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::vector<std::uint8_t> buf(size);
		file.read(reinterpret_cast<char*>(buf.data()), size);
		file.close();

		return std::make_unique<std::vector<std::uint8_t>>(buf);
	}
}