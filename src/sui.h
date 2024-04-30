#ifndef SUI_H
#define SUI_H
#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

enum class ExecutableFormat { kELF, kMachO, kPE, kUnknown };

typedef int (*Write)(const uint8_t* data, size_t size, void* user_data);

#ifdef __cplusplus
extern "C" {
#endif

ExecutableFormat get_executable_format(const char* start, size_t length);

int inject_into_elf(const uint8_t* executable_ptr, size_t executable_size,
                    const char* note_name_ptr, size_t note_name_size,
                    const uint8_t* data_ptr, size_t data_size, bool overwrite,
                    void* user_data, Write write);

int inject_into_macho(const uint8_t* executable_ptr, size_t executable_size,
                      const char* segment_name_ptr, size_t segment_name_size,
                      const char* section_name_ptr, size_t section_name_size,
                      const uint8_t* data_ptr, size_t data_size, bool overwrite,
                      void* user_data, Write write);

int inject_into_pe(const uint8_t* executable_ptr, size_t executable_size,
                   const char* resource_name_ptr, size_t resource_name_size,
                   const uint8_t* data_ptr, size_t data_size, bool overwrite,
                   void* user_data, Write write);

#ifdef __cplusplus
}
#endif

#endif  // SUI_H
