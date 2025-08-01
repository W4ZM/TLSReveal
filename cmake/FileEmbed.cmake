if(NOT DEFINED target_dll)
  message(FATAL_ERROR "couldn't find target.dll !")
endif()

# the content from our example dll file has been encoded using HEX.
file(READ "${target_dll}" content HEX)


# store each byte as a separate element in a CMake list 
# so that we can work with the data easier.
# This uses the regex of 2 hex digits 
# and matches all occurrences of the matched regex into a list called SEPARATED_HEX.
string(REGEX MATCHALL "([A-Fa-f0-9][A-Fa-f0-9])" SEPARATED_HEX ${content})

# Create a counter so that we only have 16 hex bytes per line
set(counter 0)
# Iterate through each of the bytes from the source file
foreach (hex IN LISTS SEPARATED_HEX)
	# Write the hex string to the line with an 0x prefix
	# and a , postfix to seperate the bytes of the file.
    string(APPEND output_c "0x${hex},")
    # Increment the element counter before the newline.
    math(EXPR counter "${counter}+1")
    if (counter GREATER 16)
    	# Write a newline so that all of the array initializer
    	# gets spread across multiple lines.
        string(APPEND output_c "\n    ")
        set(counter 0)
    endif ()
endforeach ()

# Generate the contents that will be contained in the source file.
set(output_c "
#include \<cstdint\>

uint8_t dll_data[] = {
    ${output_c}
};

unsigned long long dll_size = sizeof(dll_data);
")

# Generate the contents that will be contained in the header file.
set(output_h [=[
#pragma once
#include <cstdint>

extern uint8_t dll_data[];
extern unsigned long long dll_size;
]=])

# Geenrate the hpp and cpp files
file(WRITE "${source_dir}/dll.cpp" "${output_c}")
file(WRITE "${source_dir}/dll.hpp" "${output_h}")
