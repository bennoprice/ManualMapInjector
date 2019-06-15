#include <Windows.h>
#include <iostream>
#include <string_view>
#include "util.hpp"
#include "binary_file.hpp"
#include "portable_executable.hpp"

namespace injector
{
	//
	// loaded executable
	//
	portable_executable::loaded_executable::loaded_executable(std::shared_ptr<portable_executable> portable_executable, std::uint64_t image_base)
		: _portable_executable(portable_executable)
		, _image_base(image_base)
	{ }

	std::vector<portable_executable::loaded_executable::relocation> portable_executable::loaded_executable::get_relocations() const
	{
		std::vector<relocation> relocations;

		auto section = _portable_executable->get_nt_headers()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		auto base_relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(_image_base + section.VirtualAddress);

		while (base_relocation < base_relocation + section.Size && base_relocation->SizeOfBlock > 0)
		{
			std::vector<relocation::descriptor> descs;

			auto count = (base_relocation->SizeOfBlock - 8) >> 1;
			auto items = reinterpret_cast<relocation::descriptor*>(base_relocation + 1);
			for (auto i = 0u; i < count; ++i)
			{
				auto type = items[i].type;
				if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64)
					descs.emplace_back(items[i]);
			}
			relocations.push_back({ base_relocation->VirtualAddress, descs });
			base_relocation += base_relocation->SizeOfBlock;
		}
		return relocations;
	}

	std::vector<portable_executable::loaded_executable::module_import> portable_executable::loaded_executable::get_imports() const
	{
		std::vector<module_import> imports;

		auto section = _portable_executable->get_nt_headers()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		auto import_table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(_image_base + section.VirtualAddress);

		for (; import_table->Name; ++import_table)
		{
			std::vector<module_import::function> funcs;

			auto entry = reinterpret_cast<IMAGE_THUNK_DATA64*>(_image_base + import_table->OriginalFirstThunk);
			for (auto i = 0u; entry->u1.AddressOfData; i += sizeof(std::uint64_t), ++entry)
			{
				auto import_by_name = PIMAGE_IMPORT_BY_NAME(_image_base + entry->u1.AddressOfData);
				auto name = (entry->u1.Ordinal < IMAGE_ORDINAL_FLAG64 && import_by_name->Name[0]) ?
					reinterpret_cast<const char*>(import_by_name->Name) :
					reinterpret_cast<const char*>(entry->u1.AddressOfData);
				funcs.push_back({ name, import_table->FirstThunk + i });
			}
			imports.push_back({ reinterpret_cast<char*>(_image_base + import_table->Name), funcs });
		}
		return imports;
	}

	//
	// portable executable
	//
	portable_executable::portable_executable(std::wstring_view path)
	{
		_buffer = binary_file::read_file(path);
		if (!_buffer)
			util::exception("[-] failed to open file.");
		std::cout << "[+] streamed file to memory" << std::endl;

		_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(_buffer->data());
		_nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(_buffer->data() + _dos_header->e_lfanew);

		if (_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			util::exception("[-] binary invalid.");
		if (_nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			util::exception("[-] binary is not x64.");
		// add dll check
	}

	std::vector<IMAGE_SECTION_HEADER> portable_executable::get_sections() const
	{
		std::vector<IMAGE_SECTION_HEADER> sections;
		auto section_ptr = reinterpret_cast<IMAGE_SECTION_HEADER*>(_nt_headers + 1);
		for (auto i = 0u; i < _nt_headers->FileHeader.NumberOfSections; ++i)
			sections.emplace_back(section_ptr[i]);
		return sections;
	}

	IMAGE_DOS_HEADER* portable_executable::get_dos_header() const
	{
		return _dos_header;
	}

	IMAGE_NT_HEADERS* portable_executable::get_nt_headers() const
	{
		return _nt_headers;
	}

	std::uint64_t portable_executable::get_buffer() const
	{
		return reinterpret_cast<std::uint64_t>(_buffer->data());
	}
}