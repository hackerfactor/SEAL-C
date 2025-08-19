/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling Matroska files.
 Matroska includes WebM, WKM, WKA

 Matroska uses a weird encoding method for numeric values (EBML).
 See _MaReadData().
 The position of the first on-bit identifies the length of the value.
 The remaining bits in the first byte start the value.

 Matroska does NOT have any standard comment, EXIF, or XMP support.
 Ref: https://www.matroska.org/technical/tagging.html
 But, any app can define their own chunk!
 
 All chunks have the following format:
   ma-byte: tag/identifier
   ma-byte: length
	   length of 0 means no data.
   length bytes

 Unknown chunks are ignored by processing software!

 A SEAL record can exist:
   - tag 0x05345414C (SEAL), encoded as 0x085345414C
 The value of the SEAL chunk is a "<seal .../>" record.

 For signing?
  - If finalized and no previous signature, add SEAL record at
    the beginning of the file.
  - If appending or finalizing an already-signed file,
    append the SEAL record at the end of the file.

 ===============================
 Feedback from Phil Harvey (exiftool):
 > Typically all metadata comes before the first cluster, and by default ExifTool won't read it if it comes afterwards.

 I'm going to insert it after the Header and any prior SEAL records,
 but before any other chunks.
 HOWEVER, this prevents appending.
 I also did some playing with mkvmerge. It doesn't support
 true appending. It seems to always rewrites and combines elements.

 However, if you want to append, then sign at the end.
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
 _MaReadData(): Read a variable-length value.
 Updates Offset.
 **************************************/
size_t _MaReadData     (mmapfile *Mmap, size_t *Offset)
{
  size_t Val=0;
  byte Dat;
  int b;

  if (Offset[0] >= Mmap->memsize) return((size_t)(-1));
  Dat = Mmap->mem[Offset[0]];
  if (Dat==0) return((size_t)(-1)); /* invalid */
  for(b=0; (b < 8) && !(Dat & (1<<(7-b))); b++) ;
  Val = Dat & ~((0xff << (7-b)));
  b--; Offset[0]++;
  while((b >= 0) &&
	(Offset[0] < Mmap->memsize))
	{
	Val <<= 8;
	Val |= Mmap->mem[Offset[0]];
	b--; Offset[0]++;
	}
  return(Val);
} /* _MaReadData() */

/**************************************
 _MaWriteData(): Write a variable-length value.
 Updates Offset.
 **************************************/
sealfield *	_MaWriteData	(sealfield *Rec, const char *Field, size_t Value)
{
  size_t MaxValue;
  int i, num_bytes;
  int mask = 0xff;
  sealfield *v;

  // Determine the number of bytes to write
  num_bytes=1;
  MaxValue=127;
  while((num_bytes < 8) && (Value >= MaxValue))
	{
	MaxValue = (MaxValue<<7) | 0xff;
	num_bytes++;
	}

  Rec = SealAlloc(Rec,Field,num_bytes,'x'); // allocated and cleared
  v = SealSearch(Rec,Field);

  // Write the bytes
  v->Value[0] = 1 << (8 - num_bytes);
  for(i=1; i < num_bytes; i++)
	{
	v->Value[num_bytes - i] = Value & 0xFF;
	Value >>= 8;
	mask >>= 1;
	}
  v->Value[0] |= Value & 0xFF & mask;

  return(Rec);
} /* _MaWriteData() */

/**************************************
 _Matroskawalk(): Given a Matroska, walk the structures.
 Evaluate any SEAL or text chunks.
 **************************************/
sealfield *	_Matroskawalk	(sealfield *Args, mmapfile *Mmap)
{
  size_t iTag,iLen;
  size_t Offset=0;

  while(Offset < Mmap->memsize)
    {
    iTag = _MaReadData(Mmap,&Offset);
    if (iTag == (size_t)(-1)) { break; } // invalid
    iLen = _MaReadData(Mmap,&Offset);
    if (iLen == (size_t)(-1)) { break; } // invalid
    if (Offset+iLen > Mmap->memsize) { break; } // overflow

    if (iTag == 0xa45dfa3) // if Header chunk
	{
	Args = SealSetIindex(Args,"@MatInsert",0,Offset+iLen);
	}
    else if (iTag == 0x5345414C) // if SEAL chunk
	{
	// Process possible SEAL record.
	Args = SealVerifyBlock(Args, Offset, Offset+iLen, Mmap, NULL);
	Args = SealSetIindex(Args,"@MatInsert",0,Offset+iLen);
	}

    Offset+=iLen;
    }

  return(Args);
} /* _Matroskawalk() */

#pragma GCC visibility pop

/**************************************
 Seal_isMatroska(): Is this file a Matroska?
 Returns: true or false.
 **************************************/
bool	Seal_isMatroska	(mmapfile *Mmap)
{
  if (!Mmap || (Mmap->memsize < 16)) { return(false); }

  /* header begins with "\x1A\x45\xDF\xA3" */
  if (memcmp(Mmap->mem,"\x1A\x45\xDF\xA3",4)) { return(false); } /* not a Matroska! */
  return(true);
} /* Seal_isMatroska() */

/**************************************
 Seal_Matroskasign(): Sign a Matroska.
 Insert a Matroska signature.
 **************************************/
sealfield *	Seal_Matroskasign	(sealfield *Args, mmapfile *MmapIn)
{
  /*****
   Signing a Matroska is really easy:
   Add the signed block to the end.
   The only hard part is computing the encoded integers for tag and length.
   *****/
  const char *fname;
  sealfield *rec; // SEAL record
  char *Opt;
  mmapfile *MmapOut;
  size_t InsertOffset=0;

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
  InsertOffset = SealGetIindex(Args,"@MatInsert",0);
  Args = SealDel(Args,"@MatInsert"); // no longer needed

  Args = SealDel(Args,"b");
  if (strchr(SealGetText(Args,"@sflags"),'F')) // if exists, then append
	{
	// if appending, overlap signatures to prevent insertion attacks.
	Args = SealSetText(Args,"b","P");
	InsertOffset = MmapIn->memsize; // insert at end of file
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
	// Matroska doesn't support true appending.
	Args = SealAddText(Args,"b",",s~s+3"); // +3 for '"/>'
	InsertOffset = MmapIn->memsize; // insert at end of file
	//fprintf(stderr," ERROR: This format (Matroska) does not support appending. Skipping.\n");
	}

  // Get the record
  Args = SealRecord(Args); // get placeholder

  // Create the block
  Args = _MaWriteData(Args,"@BLOCK",0x5345414C); // encode "SEAL" tag
  Args = _MaWriteData(Args,"@@iLen",SealGetSize(Args,"@record")); // encode length
  rec = SealSearch(Args,"@@iLen");
  Args = SealAddBin(Args,"@BLOCK",rec->ValueLen,rec->Value);
  Args = SealDel(Args,"@@iLen");
  // Make '@s' relative to block
  SealIncIindex(Args, "@s", 0, SealGetSize(Args,"@BLOCK"));
  SealIncIindex(Args, "@s", 1, SealGetSize(Args,"@BLOCK"));
  // Add record
  rec = SealSearch(Args,"@record");
  Args = SealAddBin(Args,"@BLOCK",rec->ValueLen,rec->Value);
  SealSetType(Args,"@BLOCK",'x');
 
  MmapOut = SealInsert(Args,MmapIn,InsertOffset);
  if (MmapOut)
    {
    // Sign it!
    SealSign(Args,MmapOut,NULL);
    MmapFree(MmapOut);
    }
  
  return(Args);
} /* Seal_Matroskasign() */

/**************************************
 Seal_Matroska(): Process a Matroska.
 Reads every seal signature.
 If signing, add the signature before the IEND tag.
 **************************************/
sealfield *	Seal_Matroska	(sealfield *Args, mmapfile *Mmap)
{
  // Make sure it's a Matroska.
  if (!Seal_isMatroska(Mmap)) { return(Args); }

  // This identifies where to insert SEAL.
  Args = _Matroskawalk(Args, Mmap);

  /*****
   Sign as needed
   *****/
  Args = Seal_Matroskasign(Args,Mmap); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_Matroska() */

