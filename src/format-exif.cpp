/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling EXIF.

 EXIF isn't (usually) a standalone format.
 It's a common metadata format used by lots of different file formats.

 EXIF contains a one or more Image file directories (IFDs).
 The first one is IFD0.

 EXIF contains a TIFF header:
   2 byte endian: "II" for little endian, "MM" for big endian.
     (II for Intel, which uses little endian.
     MM for Motorola, which uses big endian.)
     All other size and values are in this endian.
   2 bytes: value 42 (II: 0x2a 0x00; MM: 0x00 0x2a)
   4 bytes: offset to IFD0 (minimum should be "8" to skip this header).

 Each IFD contains:
   2 byte: number of entries
   Each entry is 12 bytes:
     2 byte tag
     2 byte type
     4 byte size
     4 byte: data or offset
       If size <= 4, then this is the data.
       If size > 4, then this is the offset to the data.
   
 SEAL: Only cares about tag 0xcea1.
 The type should be "1" (ASCII text), but this decoder
 ignores the type.
 ************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "seal.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"
#include "files.hpp"
#include "formats.hpp"

/**************************************
 Seal_Exif(): Process a EXIF.
 **************************************/
sealfield *	Seal_Exif	(sealfield *Args, mmapfile *MmapFile, uint32_t ExifStart, uint32_t ExifSize)
{
  #define Read16(x) ((Endian==1234) ? readle16(x) : readbe16(x))
  #define Read32(x) ((Endian==1234) ? readle32(x) : readbe32(x))

  mmapfile MmapExif;
  int Endian;
  uint16_t Tag,Type,MaxEntries,e;
  uint32_t EntrySize,EntryValue,Offset;

  // Make sure it's a EXIF.
  if (MmapFile->memsize < ExifStart+ExifSize) { return(Args); } // invalid offsets
  MmapExif.mem = MmapFile->mem + ExifStart;
  MmapExif.memsize = ExifSize;
  if (MmapExif.memsize < 8+2+12) { return(Args); } // header + count + 1 entry

  // Read TIFF header
  // Endian values consistent with Gnu.
  if (!memcmp(MmapExif.mem,"II*\0",4)) { Endian=1234; } // little endian
  else if (!memcmp(MmapExif.mem,"MM\0*",4)) { Endian=4321; } // big endian
  else { return(Args); } // unknown endian.

  Offset = Read32(MmapExif.mem+4);
  if (Offset < 8) { return(Args); } // bad offset
  if (Offset+2+12 > MmapExif.memsize) { return(Args); } // overflow

  // Read IFD0
  MaxEntries = Read16(MmapExif.mem+Offset);
  Offset+=2;

  // Process every entry
  for(e=0; e < MaxEntries; e++)
    {
    if (Offset+e*12+12 > MmapExif.memsize) { break; } // overflow
    Tag  = Read16(MmapExif.mem + Offset + e*12 + 0);
    Type = Read16(MmapExif.mem + Offset + e*12 + 2);
    EntrySize = Read32(MmapExif.mem + Offset + e*12 + 4);
    EntryValue = Read32(MmapExif.mem + Offset + e*12 + 8);

    if (EntrySize <= 4) { continue; } // SEAL records are more than 4 bytes
    if (EntryValue + EntrySize > MmapExif.memsize) { continue; } // overflow

    switch(Type)
	{
	case 1: /* unsigned byte */
        case 2: /* ascii string */
        case 6: /* signed byte */
        case 7: break;    /* undefined */
	default: continue; /* unsupported for SEAL */
	}

    // Look for SEAL tag (or text comment)
    if ((Tag == 0xcea1) || // SEAL code
	(Tag == 0x9286) || // User Comment (deprecated)
	(Tag == 0xfffe)) // generic Comment
	{
	Args = SealVerifyBlock(Args, ExifStart+EntryValue, ExifStart+EntryValue+EntrySize, MmapFile, NULL);
	}
    }

  return(Args);
} /* Seal_Exif() */

