#pragma once
#include <vector>
#include <memory>

namespace binary_file
{
	std::unique_ptr<std::vector<std::uint8_t>> read_file(std::wstring_view path);
}