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

sealfield *	Seal_Manual	(sealfield *Args);

bool		Seal_isPNG	(mmapfile *Mmap);
sealfield *	Seal_PNG	(sealfield *Args, mmapfile *MmapIn);

bool		Seal_isJPEG	(mmapfile *Mmap);
sealfield *	Seal_JPEG	(sealfield *Args, mmapfile *MmapIn);

bool		Seal_isGIF	(mmapfile *Mmap);
sealfield *	Seal_GIF	(sealfield *Args, mmapfile *MmapIn);

bool		Seal_isRIFF	(mmapfile *Mmap);
sealfield *	Seal_RIFF	(sealfield *Args, mmapfile *MmapIn);

bool		Seal_isMatroska	(mmapfile *Mmap);
sealfield *	Seal_Matroska	(sealfield *Args, mmapfile *MmapIn);

bool		Seal_isBMFF	(mmapfile *Mmap);
sealfield *	Seal_BMFF	(sealfield *Args, mmapfile *MmapIn);

bool		Seal_isPDF	(mmapfile *Mmap);
sealfield *	Seal_PDF	(sealfield *Args, mmapfile *MmapIn);

bool		Seal_isPPM	(mmapfile *Mmap);
sealfield *	Seal_PPM	(sealfield *Args, mmapfile *MmapIn);

#endif

