#pragma once
#include <vector>

namespace injector
{
	class portable_executable
	{
	public:
		class loaded_executable
		{
		private:
			struct relocation
			{
				struct descriptor
				{
					std::uint16_t offset : 12;
					std::uint16_t type : 4;
					std::uint16_t get_offset()
					{
						return offset % 0x1000;
					}
				};
				std::uint32_t rva;
				std::vector<descriptor> descs;
			};

			struct module_import
			{
				struct function
				{
					std::string_view name;
					std::uint32_t rva;
				};
				std::string_view name;
				std::vector<function> funcs;
			};
		public:
			explicit loaded_executable(std::shared_ptr<portable_executable> portable_executable, std::uint64_t image_base);
			std::vector<relocation> get_relocations() const;
			std::vector<module_import> get_imports() const;
		private:
			std::shared_ptr<portable_executable> _portable_executable;
			std::uint64_t _image_base;
		};

		explicit portable_executable(std::wstring_view path);
		std::vector<IMAGE_SECTION_HEADER> get_sections() const;
		IMAGE_DOS_HEADER* get_dos_header() const;
		IMAGE_NT_HEADERS* get_nt_headers() const;
		std::uint64_t get_buffer() const;
	private:
		IMAGE_DOS_HEADER* _dos_header;
		IMAGE_NT_HEADERS* _nt_headers;
		std::unique_ptr<std::vector<std::uint8_t>> _buffer;
	};
}