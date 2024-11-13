/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling GIF files.

 GIF is not very consistent in formatting structure.
 (Don't blame GIF; it's one of the first image formats.
 It was created in 1987, before we knew better.)
 
 Header:
   3 characters: GIF
   3 characters: version, typically "87a" or "89a".
     (Since the last version was in 1989, there shouldn't be
     any other versions.)
   2 byte width
   2 byte height
   1 byte GCT flag
     Global Color Table
	if GCTflag & 0x80, then there's a global color table (GCT)
	Bits 0x07 determines the size of the GCT.
	1 byte background color index
	1 byte aspect ratio
	GCT values

 Then comes optional extensions and fields.
    0x00: unused / skip

    0x2c: image descriptor
	NOTE: SEAL should insert before the first image descriptor.
	4 byte position
	2 byte width
	2 byte height
	1 byte LCT flag
	If LCT & 0x80, then there is a local color table.
	Bits 0x07 specify the LCT length.
	1 byte LZW code size
	Then comes the image data!
	  1 byte size
	  if size is zero, then stop.
	  else: size bytes of image data.

    0x3b: trailer
	Last byte in the file. End of image.

    0x21: labels
	Extensions that all follow the same format
	1 byte subtype
	  21.01 Text label
	  21.f9 Graphic control block
	  21.fe GIF comment block
	  21.ff Application Extension block (kitchen sink)
	  21.xx Anything else? Unknown but parse the same way.
	while 1 byte length > 0
	  read length bytes of data
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
/**************************************
 _SealWalkGIF(): Scan the header and find the offset to insert.
 Returns:
   if Args is set: Offset is in '@InsertOffset'
   if Args is NULL: returns (sealfield*)1 if GIF, or NULL if not.
 offset, or 0 on error.
 **************************************/
sealfield *	_SealWalkGIF	(sealfield *Args, mmapfile *Mmap)
{
  int ctsize; // color table size
  byte tag,subtag,length;
  size_t offset;
  size_t subtagStart, insertHere=0;

  if (!Mmap || (Mmap->memsize < 16)) { return(NULL); }

  /* header begins with GIF87a or GIF89a */
  if (memcmp(Mmap->mem,"GIF87a",6) && memcmp(Mmap->mem,"GIF89a",6)) { return(NULL); }

  /* Skip the rest of the header (I don't care!) */
  offset = 10;

  /* Process GCT flag */
  if (Mmap->mem[10] & 0x80) // if has GCT
	{
	// offset = 10 + default color index + aspect ratio + GCT size
	ctsize = 3 * (1 << ((Mmap->mem[10] & 0x7)+1) );
	offset = 13 + ctsize;
	}

  /* Process everything else! */
  while(offset < Mmap->memsize)
    {
    tag = Mmap->mem[offset]; offset++;
    if (offset >= Mmap->memsize) { break; }

    if (tag == 0x00) { ; } // skip null

    else if (tag == 0x3b) // trailer, end of image
	{
	if (!insertHere) { insertHere=offset-1; } // should never happen
	break;
	}

    else if (tag == 0x2c) // image descriptor
	{
	if (!insertHere) { insertHere = offset-1; }

	offset += 8; // position + dimensions
	if (offset >= Mmap->memsize) { break; }
	if (Mmap->mem[offset] & 0x80) // if LCT
	  {
	  ctsize = 3 * (1 << ((Mmap->mem[offset] & 0x7)+1) );
	  offset += ctsize + 1;
	  }
	else { offset++; }
	if (offset >= Mmap->memsize) { break; }
	// Now iterate over image
	length=Mmap->mem[offset]; offset++;
	while(length > 0)
	  {
	  offset += length;
	  if (offset >= Mmap->memsize) { break; }
	  length=Mmap->mem[offset]; offset++;
	  }
	}

    else if (tag == 0x21) // graphic control block
	{
	subtag = Mmap->mem[offset]; offset++;
	subtagStart = offset;
	// Now iterate over content
	length=Mmap->mem[offset]; offset++;
	while(length > 0)
	  {
	  offset += length;
	  if (offset >= Mmap->memsize) { break; }
	  length=Mmap->mem[offset]; offset++;
	  }
	// Scan for SEAL!
	if (subtag == 0xff)
	  {
	  if (offset >= Mmap->memsize) { break; }
	  Args = SealVerifyBlock(Args, subtagStart, offset, Mmap);
	  }
	}

    if (offset >= Mmap->memsize) { break; }
    }

  if (insertHere)
	{
	Args = SealSetIindex(Args,"@InsertOffset",0,insertHere);
	}

  if (Args) { return(Args); }
  return((sealfield*)1);
} /* _SealWalkGIF() */

#pragma GCC visibility pop

/**************************************
 Seal_isGIF(): Is this file a GIF?
 Returns: true or false.
 **************************************/
bool	Seal_isGIF	(mmapfile *Mmap)
{
  if (!Mmap || (Mmap->memsize < 16)) { return(false); }
  if (!memcmp(Mmap->mem,"GIF87a",6) || !memcmp(Mmap->mem,"GIF89a",6)) { return(true); }
  return(false);
} /* Seal_isGIF() */

/**************************************
 Seal_GIFsign(): Sign a GIF.
 Insert a GIF signature.
 **************************************/
sealfield *	Seal_GIFsign	(sealfield *Args, mmapfile *MmapIn)
{
  /*****
   Signing a GIF:
   It's easy to insert since the data is plain text.
   It's a 2f.ff block ("SEAL1.0" + data)

   HOWEVER:
   The block length is limited to 255 characters.
   If the length is greater than 255, then use the next character
   in the text stream as the length.

   The problem is, I don't know the last character until the signature
   is generated. The solution is to insert a slope that catches the
   end length.
   *****/
  const char *fname;
  sealfield *rec; // SEAL record
  char *Opt;
  mmapfile *MmapOut;
  size_t InsertOffset=0;

  fname = SealGetText(Args,"@FilenameOut");
  if (!fname || !fname[0] || !MmapIn) { return(Args); } // not signing

  Args = _SealWalkGIF(Args,MmapIn);
  InsertOffset = SealGetIindex(Args,"@InsertOffset",0);
  Args = SealDel(Args,"@InsertOffset");
  if (InsertOffset < 3) { return(Args); } // should never happen

  // Set the range
  Opt = SealGetText(Args,"options"); // grab options list

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
	// if starting from the beginning of the file
	Args = SealSetText(Args,"b","F");
	}
  // Range covers signature and end of record.
  Args = SealAddText(Args,"b","~S");

  // Check for appending
  if (!Opt || !strstr(Opt,"append")) // if not append
	{
	Args = SealAddText(Args,"b",",s~f");
	}
  else
	{
	// GIF doesn't support true appending.
	Args = SealAddText(Args,"b",",s~s+3"); // +3 for '"/>'
	//fprintf(stderr," ERROR: This format (GIF) does not support appending. Skipping.\n");
	}

  // Get the record
  Args = SealRecord(Args); // get placeholder

  // Create the block
  Args = SealSetBin(Args,"@BLOCK",2,(const byte*)"\x21\xff"); // 21.ff tag
  SealAddC(Args,"@BLOCK",(byte)0xff); // assume initial length with padding is >= 255
  Args = SealAddText(Args,"@BLOCK","SEAL1.0");

  // Make '@s' relative to block
  rec = SealSearch(Args,"@BLOCK");
  SealIncIindex(Args, "@s", 0, rec->ValueLen);
  SealIncIindex(Args, "@s", 1, rec->ValueLen);
 
  // Add record
  rec = SealSearch(Args,"@record");
  Args = SealAddBin(Args,"@BLOCK",rec->ValueLen,rec->Value);
  Args = SealAddText(Args,"@BLOCK","\n");

  // Add in null slope
  {
  byte Slope[128];
  memset(Slope,0,128);
  Args = SealAddBin(Args,"@BLOCK",127,Slope);
  }

  SealSetType(Args,"@BLOCK",'x');
 
  MmapOut = SealInsert(Args,MmapIn,InsertOffset);
  if (MmapOut)
    {
    // Sign it!
    SealSign(Args,MmapOut);
    MmapFree(MmapOut);
    }
  
  return(Args);
} /* Seal_GIFsign() */

/**************************************
 Seal_GIF(): Process a GIF.
 Reads every seal signature.
 If signing, add the signature before the IEND tag.
 **************************************/
sealfield *	Seal_GIF	(sealfield *Args, mmapfile *Mmap)
{
  sealfield *a;

  // Make sure it's a GIF.
  a = _SealWalkGIF(Args,Mmap);
  if (!a) { return(Args); }
  Args = a;

  /*****
   Sign as needed
   *****/
  Args = Seal_GIFsign(Args,Mmap); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_GIF() */

