/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling file formats.
 ************************************************/
#ifndef SEAL_FORMATS_HPP
#define SEAL_FORAMTS_HPP

#include <stdlib.h>
#include "seal.hpp"
#include "files.hpp"

bool		Seal_isPNG	(mmapfile *Mmap);
sealfield *	Seal_PNG	(sealfield *Args, mmapfile *Mmap);

#endif

