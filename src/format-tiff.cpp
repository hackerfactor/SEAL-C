/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling TIFF.

 Ref: https://www.fileformat.info/format/tiff/egff.htm

 TIFF has a small header and then a series of linked
 Image File Directories (IFDs).

 If a TIFF has multiple pages, then each page is a different IFD.

 DNG is a TIFF file. (If we support TIFF, then we support DNG.
 According to ExifTool, Panasonic RAW is also a TIFF, but it uses
 a different magic number. (Seriously, a 1-byte difference.)

 Many Camera-RAW formats use TIFF.

 =====
 (Of the good/bad/ugly formats, TIFF is a bad format
 because data is not stored in the IFD.)

 TIFF begins with a small header:
   2 byte endian: II or MM
   2 byte magic number: 42 ('*') in big or little endian.
   4 byte offset to first IFD.

 For tracking endian, use the Gnu notation:
   1234 = little endian
   4321 = big endian

 TIFF uses a chain of IFD records.
 Each IFD is word-aligned and contains:
   2 bytes: number of records
   For each record, 12 bytes:
     2 bytes: Tag ID
     2 bytes: Data type
	1 = bytes
	2 = ascii text
	3 = unsigned 16-bit
	4 = unsigned 32-bit
	5 = rational with two 32-bit unsinged integers
	6 = signed byte
	...
     4 bytes: Data count (numberof data bytes)
     4 bytes: Data offset
	If the count is <= 4, then this is the data.
	Otherwise, then this is the absolute offset in the file to the data.
	(And that's the bad part: absolute pointers to data.)
    After the records are 4 more bytes:
    4 bytes: offset to next IFD
	Next == 0? Done!
	watch out for loops! (Hint: IFDs should never point backwards!)

 =====
 For signing...

 Inserting a record requires moving the absolute location for all subsequent
 data and updating every pointer to the data.  And that assumes you know how
 to parse every possible tag and tag data type.
 This gets ugly really fast.

 BUT!
 I can always append a new IFD at the end of the file!
 For signing:
   1. Create a new IFD at the end.
   2. Update the last IFD pointer (0x00000000) to the new IFD.
   3. Create a single record: type 0xcea1 (ceal for seal).
   4. Store the data after the IFD with 0x00 padding to the word.

 HOWEVER!
 There's a problem...
 The "Next IFD" pointer is before the signature.
 During an append, it will be changed, breaking the signature.
 The solution?  Store the SEAL record BEFORE the IFD!


 With TIFF, unknown tags are ignored when processing, so this should work fine.

 NOTE: While this code always appends, some other tool could
 include a SEAL tag in any top-level IFD.

 NOTE: Imagemagick will complain:
    Unknown field with tag 52897 (0xcea1) encountered.
    TIFF directory is missing required "ImageLength" field.
 This is because:
   (1) it's not ignoring unknown types, and
   (2) it assumes the ".tiff" extension only contains images.

 These messages are inconsistent with the TIFF specifations.
   Ref: https://download.osgeo.org/libtiff/doc/TIFF6.pdf

   Page 8: Private tags are numbered 32768 or higher (0x8000).
   SEAL uses 0xcea1, so it's a private tag.

   Page 26 says that "Other fields" are permitted.
   "TIFF readers must also be prepared to encounter and ignore private
   fields not described in the TIFF specification."
   Imagemagick isn't properly ignoring unknown private tags.
 
   Beginning on page 21: ImageLength is only required if the IFD
   defines an image.
   The SEAL IFD entry does not define an image, so the length is
   not required.

 I like Imagemagick, but in this case, they are wrong.
 (Imagemagick generates the same kinds of warnings if you use a
 Canon RAW and change the extension from ".CR2" to ".TIFF".)

 =====
 For verifying:

 Find every top-level IFD (main chain, not IFD nesting).
 If the tag is 0xcea1 AND the data type is an 8-bit value
 (types 1, 2, or 6), then parse then check the SEAL record.

 Do NOT process any EXIF (tag 0x02bc), IPTC (0x83bb), or XMP (0x8769) data.
 Why not? Ambiguous! We don't know if it refers to the TIFF or some content
 in a particular IFD.

 Do NOT process any other tags.
 Why not? We're not rendering!

 Do NOT process any nested IFDs.
 Why not? Scope! They are guaranteed to not be global.
 And we don't know if we know every tag that could be a nested IFD.
 ************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "seal.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"
#include "files.hpp"
#include "formats.hpp"

#define Read16(x) ((Endian==1234) ? readle16(x) : readbe16(x))
#define Read32(x) ((Endian==1234) ? readle32(x) : readbe32(x))

#pragma GCC visibility push(hidden)

/**************************************
 _TIFFwalk(): Given a TIFF, walk the structures.
 Evaluate any SEAL or text chunks.
 Data and Pos may change during recursion, but Mmap is always source file.
 NOTE: This is recursive!
 **************************************/
sealfield *	_TIFFwalk	(sealfield *Args, int Endian, mmapfile *Mmap)
{
  /*****
   If the code got here, then we already know the header is valid.
   We know the endian from the header.
   And we know the offset to the first IFD (IFD0) looks valid.

   Start with the first IFD and start hopping!

   Store the final IFD location in Args. (In case we need to insert.)
   *****/
  size_t LinkIFDoffset,IFDoffset;
  int IFDnum=0;
  uint16_t EntryCount,e;
  uint32_t DataOffset,DataSize;

  LinkIFDoffset = 4;
  IFDoffset = Read32(Mmap->mem + LinkIFDoffset);

  while(IFDoffset > 0)
    {
    if (IFDoffset % 2)
      {
      printf("  WARNING: IFD%d is not word-aligned.\n",IFDnum);
      }

    if (IFDoffset+6 >= Mmap->memsize) // overflow
      {
      printf("  ERROR: IFD%d is truncated. Aborting.\n",IFDnum);
      return(Args);
      }

    EntryCount = Read16(Mmap->mem + IFDoffset);
    IFDoffset += 2;

    // Process every entry; look for tag 0xcea1
    // Every entry is 12 bytes
    for(e=0; e < EntryCount; e++)
      {
      if (IFDoffset+12 > Mmap->memsize) // overflow
	{
	printf("  ERROR: IFD%d is truncated. Aborting.\n",IFDnum);
	return(Args);
	}

      if (Read16(Mmap->mem+IFDoffset) == 0xcea1) // if SEAL tag
        {
	switch(Read16(Mmap->mem+IFDoffset+2)) // check type
	  {
	  case 1: // unsigned binary
	  case 2: // ascii
	  case 6: // signed binary
		break;
	  default: // unknown encoding
		{
		printf("  WARNING: IFD%d entry %u contains a SEAL record with unknown encoding. Assuming binary..\n",IFDnum,e);
		}
		break;
	  }
	DataSize = Read32(Mmap->mem + IFDoffset + 4);
	DataOffset = Read32(Mmap->mem + IFDoffset + 8);
	if (DataOffset+ DataSize > Mmap->memsize) // truncated!
	  {
	  long signum;
	  signum = SealGetIindex(Args,"@s",2);
	  printf(" SEAL record #%ld is invalid: Truncated.\n",signum);
	  Args = SealSetIindex(Args,"@s",2,signum+1);
	  }
	else
	  {
	  // Verify record!
	  Args = SealVerifyBlock(Args, DataOffset, DataOffset+DataSize, Mmap);
	  }
	} // if SEAL tag
      IFDoffset += 12;
      }

    // Next IFD!
    if (IFDoffset+4 > Mmap->memsize)
	{
	printf("  ERROR: IFD%d is truncated. Aborting.\n",IFDnum);
	return(Args);
	}
    LinkIFDoffset = IFDoffset;
    IFDoffset = Read32(Mmap->mem+IFDoffset);
    if (IFDoffset == 0) { ; } // found end! Handled later
    else if (IFDoffset < LinkIFDoffset) // loop found
	{
	printf("  ERROR: IFD%d contains a loop. Aborting.\n",IFDnum);
	return(Args);
	}
    IFDnum++;
    } // while processing IFDs

  if (IFDoffset == 0) // found end!
	{
	Args = SealSetIindex(Args,"@TIFFIFD",0,LinkIFDoffset); // store end for insertions
	}
  return(Args);
} /* _TIFFwalk() */

#pragma GCC visibility pop

/**************************************
 Seal_isTIFF(): Is this file a TIFF?
 Returns: endian or 0
 **************************************/
int	Seal_isTIFF	(mmapfile *Mmap)
{
  int Endian;
  if (!Mmap || (Mmap->memsize < 16)) { return(0); }

  if (!memcmp(Mmap->mem,"II",2)) { Endian=1234; }
  else if (!memcmp(Mmap->mem,"MM",2)) { Endian=4321; }
  else { return(0); }

  switch(Read16(Mmap->mem+2))
    {
    /* Why 42? That is the arbitrary number chosen by TIFF. */
    case 0x002a: break; /* Standard TIFF: Type 42. Includes DNG. */

    /* http://www.sno.phy.queensu.ca/~phil/exiftool/TagNames/Panasonic.html */
    case 0x0055: break; /* Panasonic and Leica camera RAW format */

    default: return(0); // not TIFF
    }

  uint32_t u32;
  u32 = Read32(Mmap->mem+4);
  if (u32 % 2) { return(0); } // must be word aligned
  if (u32+2 > Mmap->memsize) { return(0); } // first IFD is overflow
  return(Endian);
} /* Seal_isTIFF() */

/**************************************
 Seal_TIFFsign(): Sign a TIFF.
 Insert a TIFF signature.
 **************************************/
sealfield *	Seal_TIFFsign	(sealfield *Args, int Endian, mmapfile *MmapIn)
{
  char *Opt;
  sealfield *rec, *block; // SEAL record
  mmapfile *MmapOut;
  const char *fname;
  uint32_t IFDlink,IFDoffset;

  /*****
   To insert:
   Create a new a new IFD.
   It has one record: 0xceal
   The data for the record is the SEAL record.

   Append this to the end of the file.
   Update the previous IFD link location to point to this IFD.
   *****/
  IFDlink = SealGetIindex(Args,"@TIFFIFD",0);
  if (IFDlink == 0) { return(Args); } // cannot sign

  fname = SealGetText(Args,"@FilenameOut");
  if (!fname || !fname[0] || !MmapIn) { return(Args); } // not signing

  // Set the range
  /*****
   Determine the byte range for the digest.
   The first record should start from the start of the file.
   The last record goes to the end of the file. Unless...
   Unless it is appending.
   *****/
  Args = SealDel(Args,"b");
  if (strchr(SealGetText(Args,"@sflags"),'F')) // if exists, then append
	{
	// if appending, overlap signatures to prevent insertion attacks.
	Args = SealSetText(Args,"b","P");
	}
  else
	{
	// start from the beginning of the file
	Args = SealSetText(Args,"b","F");
	}
  Args = SealAddText(Args,"b","~S"); // F~S or P~S

  // Check for appending
  Opt = SealGetText(Args,"options"); // grab options list
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

  /*****
   Create the IFD block
   I know it needs:
     2 bytes for count (will be "1")
     12 bytes for IFD entry (will be tag 0xcea1, type 2 ASCII text)
     4 bytes for next IFD (zero)
     and SEAL record padded to 16-bit boundary.
   That's 18 bytes + record size
   *****/
  rec = SealSearch(Args,"@record");
  Args = SealDel(Args,"@BLOCK");

  Args = SealAlloc(Args,"@BLOCK",18 + rec->ValueLen + (rec->ValueLen % 2),'x');
  block = SealSearch(Args,"@BLOCK");

  // Store record *before* the IFD
  memcpy(block->Value,rec->Value,rec->ValueLen);
  // Make "@s" relative to the start of the block (Already done!)
  IFDoffset = rec->ValueLen + (rec->ValueLen % 2);

  // Now fill it using the correct endian!
  if (Endian == 1234) // little endian
	{
	writele16(block->Value+IFDoffset+0,1); // 1 entry in the IFD
	writele16(block->Value+IFDoffset+2,0xcea1); // tag 0xcea1
	writele16(block->Value+IFDoffset+4,2); // type 2: ascii text
	writele32(block->Value+IFDoffset+6,rec->ValueLen + (rec->ValueLen % 2)); // data size with padding
	writele32(block->Value+IFDoffset+10,MmapIn->memsize); // data offset is right after this IFD
	// Don't need to write 0 for next IFD
	}
  else // big endian
	{
	writebe16(block->Value+IFDoffset+0,1); // 1 entry in the IFD
	writebe16(block->Value+IFDoffset+2,0xcea1); // tag 0xcea1
	writebe16(block->Value+IFDoffset+4,2); // type 2: ascii text
	writebe32(block->Value+IFDoffset+6,rec->ValueLen + (rec->ValueLen % 2)); // data size with padding
	writebe32(block->Value+IFDoffset+10,MmapIn->memsize); // data offset is right after this IFD
	// Don't need to write 0 for next IFD
	}
  IFDoffset += MmapIn->memsize; // make the new offset relative to the new file

  // Write the output; append new record to the end of the file
  MmapOut = SealInsert(Args,MmapIn,MmapIn->memsize);
  if (MmapOut)
    {
    // Update previous "next IFD" with current IFD location
    if (Endian == 1234) { writele32(MmapOut->mem + IFDlink, IFDoffset); }
    else { writebe32(MmapOut->mem + IFDlink, IFDoffset); }
    // Sign it!
    SealSign(Args,MmapOut);
    MmapFree(MmapOut);
    }
  
  return(Args);
} /* Seal_TIFFsign() */

/**************************************
 Seal_TIFF(): Process a TIFF.
 Reads every seal signature.
 If signing, add the signature before the IEND tag.
 **************************************/
sealfield *	Seal_TIFF	(sealfield *Args, mmapfile *Mmap)
{
  // Make sure it's a TIFF.
  int Endian;
  Endian = Seal_isTIFF(Mmap);
  if (!Endian) { return(Args); }

  Args = _TIFFwalk(Args, Endian, Mmap);

  /*****
   Sign as needed
   *****/
  Args = Seal_TIFFsign(Args, Endian, Mmap); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  Args = SealDel(Args,"@TIFFIFD"); // remove temperary value
  return(Args);
} /* Seal_TIFF() */

