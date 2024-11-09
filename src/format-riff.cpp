/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling RIFF files.
 RIFF includes WAV, WebP, some AVI files, etc.

 All chunks have the following format:
   4-byte: identifier (four-character code: FourCC)
   4-byte: length in little endian; excludes FourCC and length!
	   length of 0 means no data.
   length bytes
   padding: if length is not even (16-bit aligned)

 The outer chunk is "RIFF".
   4-byte: RIFF
   4-byte: length of file in little endian

 "RIFF" and "LIST" are special chunks that permits nesting.
   No other chunks are nested by default.
   RIFF includes the entire file.
   LIST usually includes info fields, like
     ICMT = Comment
     INAM = Title

 Unknown FourCC chunks are ignored by processing software!

 A SEAL record can exist:
   - "SEAL" chunk under the top-level RIFF.
   - Any chunk under a "LIST" chunk under the top-level RIFF.
 The value of the SEAL chunk is a "<seal .../>" record.
 ************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "seal.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"
#include "files.hpp"
#include "formats.hpp"

#pragma GCC visibility push(hidden)

const char *_RIFFvalidate[] = {
	"SEAL", // SEAL record
	"XMP ", // XMP data
	// INFO fields
	"IARL", // "Archival location"
	"IART", // "Artist"
	"ICDS", // "Costime designer"
	"ICMS", // "Commissioned by"
	"ICMT", // "Comment"
	"ICOP", // "Copyright"
	"ICRD", // "Date Created"
	"ICRP", // "Cropped"
	"IDIM", // "Dimensions"
	"IDIT", // "Original date/time"
	"IDPI", // "DPI"
	"IEDT", // "Edited by"
	"IENG", // "Engineer"
	"IGNR", // "Genre"
	"IKEY", // "Keywords"
	"ILGT", // "Lightness"
	"IMED", // "Medium"
	"IMUS", // "Music by"
	"INAM", // "Title"
	"IPDS", // "Production Engineer"
	"IPLT", // "Palette colors"
	"IPRD", // "Product"
	"IPRO", // "Produced by"
	"ISBJ", // "Subject"
	"ISFT", // "Software"
	"ISGN", // "Secondary genre"
	"ISHP", // "Sharpness"
	"ISMP", // "Time code"
	"ISRC", // "Source"
	"ISRF", // "Source from"
	"ISTD", // "Production Studio"
	"ISTR", // "Starring"
	"ITCH", // "Technician"
	"IWEB", // "Internet Address"
	"IWRI", // "Written by"
	NULL
	};

/**************************************
 _RIFFwalk(): Given a RIFF, walk the structures.
 Evaluate any SEAL or text chunks.
 Data and Pos may change during recursion, but Mmap is always source file.
 NOTE: This is recursive!
 **************************************/
sealfield *	_RIFFwalk	(sealfield *Args, size_t PosStart, size_t PosEnd, int Depth, mmapfile *Mmap)
{
  byte *Data; // simplify indexing
  size_t size;
  int r;

  while(PosStart+8 < PosEnd)
    {
    Data = Mmap->mem+PosStart;

    size = readle32(Data+4);
    if (PosStart+size > PosEnd) { break; } // overflow
    //DEBUGPRINT("%*s%.4s: %.4s",Depth*2,"",Data,Data+8);

    if ((Depth < 1) && !memcmp(Data,"RIFF",4)) // iterate on RIFF!
	{
	if (size > 4)
	  {
	  // "RIFF" size and 4-byte type
	  //DEBUGPRINT("%*s%.4s: %.4s",Depth*2,"",Data,Data+8);
	  Args = _RIFFwalk(Args, PosStart+12, PosStart+12+size, Depth+1, Mmap);
	  }
	}
    else if ((Depth < 2) && !memcmp(Data,"LIST",4)) // iterate on LIST!
	{
	if (size > 4)
	  {
	  // "LIST" size and 4-byte type
	  //DEBUGPRINT("%*s%.4s: %.4s",Depth*2,"",Data,Data+8);
	  // only recurse on "INFO"
	  if (!memcmp(Data+8,"INFO",4))
	    {
	    Args = _RIFFwalk(Args, PosStart+12, PosStart+12+size, Depth+1, Mmap);
	    }
	  }
	}
    else if (!memcmp(Data,"EXiF",4)) // Special case for EXIF processing
	{
	//DEBUGPRINT("%*s%.4s",Depth*2,"",Data);
	; // TBD EXIF
	}
    else // any other field
	{
	//DEBUGPRINT("%*s%.4s",Depth*2,"",Data);
	for(r=0; _RIFFvalidate[r]; r++)
	  {
	  if (memcmp(_RIFFvalidate[r],Data,4)) { continue; }// Can it contain a SEAL record?
	  Args = SealVerifyBlock(Args, PosStart+8, PosStart+8+size, Mmap);
	  } // foreach possible chunk
	}

    // Skip size and padding
    if (size%2) { size++; } // any padding
    PosStart += 8+size;
    }

  return(Args);
} /* _RIFFwalk() */

#pragma GCC visibility pop

/**************************************
 Seal_isRIFF(): Is this file a RIFF?
 Returns: true or false.
 **************************************/
bool	Seal_isRIFF	(mmapfile *Mmap)
{
  if (!Mmap || (Mmap->memsize < 16)) { return(false); }

  /* header begins with "RIFF" */
  if (memcmp(Mmap->mem,"RIFF",4)) { return(false); } /* not a RIFF! */
  size_t size;
  size = readle32(Mmap->mem+4);
  if (size+8 != Mmap->memsize) { return(false); } /* incorrect size; corrupt or wrong format */
  return(true);
} /* Seal_isRIFF() */

/**************************************
 Seal_RIFFsign(): Sign a RIFF.
 Insert a RIFF signature.
 **************************************/
sealfield *	Seal_RIFFsign	(sealfield *Args, mmapfile *MmapIn)
{
  /*****
   Signing a RIFF is straightforward.
   1. Compute the size of the SEAL record + chunk.
   2. Increase the RIFF header's total size.
   3. Append the signature to the end.
   4. Computer the new signature's value.
   5. insert the new signature.
   *****/
  const char *fname;
  sealfield *rec, *block; // SEAL record
  char *Opt;
  mmapfile *MmapOut;
  size_t BlockLen;

  fname = SealGetText(Args,"@FilenameOut");
  if (!fname || !fname[0] || !MmapIn) { return(Args); } // not signing

  // Set the range
  Opt = SealGetText(Args,"options"); // grab options list

  /*****
   Determine the byte range for the digest.
   The first record should start from the start of the file.
   The last record goes to the end of the file. Unless...
   Unless it is appending.
   *****/
  Args = SealDel(Args,"b");
  if (SealGetCindex(Args,"@sflags",0)=='F') // if exists, then append
	{
	// if appending, overlap signatures to prevent insertion attacks.
	Args = SealSetText(Args,"b","P");
	}
  else
	{
	// if starting from the beginning of the file
	// Skip the total file length.
	Args = SealSetText(Args,"b","F~F+4,F+8");
	}
  // Range covers signature and end of record.
  Args = SealAddText(Args,"b","~S");

  // Check for appending
  if (!Opt || !strstr(Opt,"append")) // if not append
	{
	// Skip the PNG checksum and finalize to the end of file ("f")
	Args = SealAddText(Args,"b",",s~f");
	}
  else
	{
	Args = SealAddText(Args,"b",",s~s+3"); // +3 for '"/>'
	}

  // Get the record
  Args = SealRecord(Args); // get placeholder

  // Create the block
  Args = SealSetTextLen(Args,"@BLOCK",8,"SEAL...."); // record + space for data size
  // Make "@s" relative to the start of the block
  SealIncIindex(Args, "@s", 0, 8);
  SealIncIindex(Args, "@s", 1, 8);
  rec = SealSearch(Args,"@record");
  Args = SealAddBin(Args,"@BLOCK",rec->ValueLen, rec->Value);

  // pad block to 16-bit alignment
  block = SealSearch(Args,"@BLOCK");
  if (block->ValueLen % 2)
    {
    Args = SealAddC(Args,"@BLOCK",' ');
    block = SealSearch(Args,"@BLOCK");
    }

  // Set block length
  BlockLen = block->ValueLen;
  writele32(block->Value+4,BlockLen-8);

  // Write the output; append new record to the end of the file
  MmapOut = SealInsert(Args,MmapIn,MmapIn->memsize);
  if (MmapOut)
    {
    // Update file (initial RIFF block) with new size
    writele32(MmapOut->mem + 4, MmapOut->memsize - 8);
    // Sign it!
    SealSign(Args,MmapOut);
    MmapFree(MmapOut);
    }
  
  return(Args);
} /* Seal_RIFFsign() */

/**************************************
 Seal_RIFF(): Process a RIFF.
 Reads every seal signature.
 If signing, add the signature before the IEND tag.
 **************************************/
sealfield *	Seal_RIFF	(sealfield *Args, mmapfile *Mmap)
{
  // Make sure it's a RIFF.
  if (!Seal_isRIFF(Mmap)) { return(Args); }

  Args = _RIFFwalk(Args, 0, Mmap->memsize, 0, Mmap);

  /*****
   Sign as needed
   *****/
  Args = Seal_RIFFsign(Args,Mmap); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_RIFF() */

