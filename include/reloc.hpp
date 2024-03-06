#ifndef OWL_RELOC_HPP
#define OWL_RELOC_HPP

#include "master.hpp"

BOOL HasRelocation32(const LPVOID lpImage);
BOOL HasRelocation64(const LPVOID lpImage);
IMAGE_DATA_DIRECTORY GetRelocAddress32(const LPVOID lpImage);
IMAGE_DATA_DIRECTORY GetRelocAddress64(const LPVOID lpImage);

#endif