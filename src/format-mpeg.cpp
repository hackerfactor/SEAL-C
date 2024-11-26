/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling MPEG (video) and MP3 (audio) files.

 MPEG is a horribly complex format. (Makes it great for wrapping it in patents...)

 1. Raw MPEG does not have any defined method for metadata or comments.
    It's just frames of audio data.

 2. There are different types of MPEG/MPEG files: v1, v2, and v2.5.
    Each has very different formats, but they use the same frame markers.

 3. Most MP3 files use a format called 'ID3' to introduce metadata (title,
    author, copyright, etc.). However:
    - ID3v1 (obsolate) was limited to 30 characters per field.
    - ID3v2 (2.0/2.1/2.2; 2.0 is obsolete) has limited customized fields.
    - ID3v2 (2.3 and 2.4) supports user-generated text fields (the TXXX tag),
      but there are no tools that support writing it.
    (It's so complicated that even ExifTool doesn't support writing ID3.)

 MPEG frames begin with a 32-bit sync flag (u16&0xffe00000 == 0xffe00000).
 The rest of the bits &0x100000 denote different frame types.
 (See ExifTool MPEG.pm ProcessMPEGVideo() and ProcessMPEGAudio() for
 determining the type of frame.)

 This is really ambiguous.
 It's why you can often take a random binary file and play it with an MPEG player.
 (It will usually sound like static.)
 Even the length of a frame varies based on the encoding options.
 If the player sees a u32 that looks like a frame sync marker, then it will be
 played as an MPEG.
 This is also why "magic" saves MPEG detection for the very end.
 ("If it's nothing else AND it could be MPEG, then say MPEG.")

 Frames are NOT independent.
   - Each frame contains a data buffer.
   - Any bits not used by frame n are used by frame n+1!

 Okay... so what if you have data outside of an mpeg frame?
 It's ignored. It will skip anything until it finds the sync tag (0xffe0).
 That's by design.
 Great! The SEAL record can be inserted between any frame!
 You just have to find out where the frame is located. That's the hard part.
 (Unless you just append it to the end of the MPEG! FTW!)

 As an aside: C2PA cannot support raw MPEG without a remote sidecar.
 This is because the JUMBF+CBOR binary data can coincidentally contain the
 sync flag. It would cause a brief corruption (chirp!) when playing the MPEG.
 ID3v2.3 and ID3v2.4 supports user defined binary data ("PRIV" tag), but ID3v2.2
 (and earlier) does not. So C2PA would need to convert any older ID3 tags to
 newer ID3 tags, but that could break anyone else's custom tags.
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
 _SealWalkMPEG(): Scan the header and find the offset to insert.
 Returns:
   Offset is in '@InsertOffset'
 offset, or 0 on error.
 **************************************/
sealfield *	_SealWalkMPEG	(sealfield *Args, mmapfile *Mmap)
{
  size_t offset, scanStart;
  uint32_t u32;
  bool InHeader=false;

  // Check for MPEG1; permit up to 1K of garbage
  scanStart=offset=0;
  while(offset+4 <= Mmap->memsize)
    {
    u32 = readbe32(Mmap->mem+offset);
    if ((u32 & 0xffffff00) == 0x49443300) // ID3
	{
	/*****
	 ID3 format:
	 "ID3"
	 1 byte version
	 4 byte flags
	 4 byte size: size of ID3
	  Size uses 7 bits from 4 bytes: 0x0aaaaaaa
	 *****/
	if (offset+12 >= Mmap->memsize) { break; } // overflow
	int i;
	u32=0;
	// size is stored in lower 7 bits
	for(i=6; i < 10; i++)
	  {
	  if (Mmap->mem[offset+i] >= 0x80) { offset+=10; continue; } // invlid
	  u32 = (u32 << 7) | Mmap->mem[offset+i];
	  }
	u32 *= 4; // words, not bytes
	offset += u32; // skip ID3
	scanStart = offset;
	}
    else if ((u32 >= 0x000001b7) && (u32 <= 0x000001ef)) // MPEG header
	{
	if (!InHeader) { Args = SealVerifyBlock(Args, scanStart, offset, Mmap); }
	offset += 4;
	InHeader=true;
	if (u32 == 0x000001b9) { InHeader=false; } // 0x000001b7 = end of data
	}
    else if ((u32&0xffe00000)==0xffe00000) // raw MP3
	{
	if (!InHeader) { Args = SealVerifyBlock(Args, scanStart, offset, Mmap); }
	InHeader=false;
	if (((u32 & 0x180000) == 0x080000) || // 01 is a reserved version ID
	    ((u32 & 0x060000) == 0x000000) || // 00 is a reserved layer description
	    ((u32 & 0x00f000) == 0x000000) || // 0000 is the "free" bitrate index
	    ((u32 & 0x00f000) == 0x00f000) || // 1111 is a bad bitrate index
	    ((u32 & 0x000c00) == 0x000c00) || // 11 is a reserved sampling frequency
	    ((u32 & 0x000003) == 0x000002) || // 10 is a reserved emphasis
	    ((u32 & 0x060000) != 0x020000))   // layer 3 for mp3
		{ ; } // NOPE!
	// else // MP3
	offset += 4;
	scanStart=offset;
	}
    else { offset++; }
    }
  if (!InHeader) { Args = SealVerifyBlock(Args, scanStart, offset, Mmap); }

  Args = SealSetIindex(Args,"@InsertOffset",0,Mmap->memsize);
  return(Args);
} /* _SealWalkMPEG() */

#pragma GCC visibility pop

/**************************************
 Seal_isMPEG(): Is this file a MPEG?
 Returns: true or false.
 **************************************/
bool	Seal_isMPEG	(mmapfile *Mmap)
{
  size_t offset;
  uint32_t u32;
  int missed=0;

  if (!Mmap || (Mmap->memsize < 40)) { return(false); } // too small

  // Check for MPEG1; permit up to 1K of garbage
  offset=0;
  while((offset+40 < Mmap->memsize) && (missed < 1024))
    {
    u32 = readbe32(Mmap->mem+offset);
    if ((u32 & 0xffffff00) == 0x49443300) // ID3
	{
	/*****
	 ID3 format:
	 "ID3"
	 1 byte version
	 4 byte flags
	 4 byte size: size of ID3
	  Size uses 7 bits from 4 bytes: 0x0aaaaaaa
	 *****/
	if (offset+10 >= Mmap->memsize) { break; } // overflow
	int i;
	u32=0;
	// size is stored in lower 7 bits
	for(i=6; i < 10; i++)
	  {
	  if (Mmap->mem[offset+i] >= 0x80) { return(false); } // invlid
	  u32 = (u32 << 7) | Mmap->mem[offset+i];
	  }
	u32 *= 4; // words, not bytes
	offset += u32; // skip ID3
	missed=0;
	}
    else if ((u32 >= 0x000001b7) && (u32 <= 0x000001ef)) // MPEG header
	{
	return(true);
	}
    else if ((u32&0xffe00000)==0xffe00000) // raw MP3
	{
	if (((u32 & 0x180000) == 0x080000) || // 01 is a reserved version ID
	    ((u32 & 0x060000) == 0x000000) || // 00 is a reserved layer description
	    ((u32 & 0x00f000) == 0x000000) || // 0000 is the "free" bitrate index
	    ((u32 & 0x00f000) == 0x00f000) || // 1111 is a bad bitrate index
	    ((u32 & 0x000c00) == 0x000c00) || // 11 is a reserved sampling frequency
	    ((u32 & 0x000003) == 0x000002) || // 10 is a reserved emphasis
	    ((u32 & 0x060000) != 0x020000))   // layer 3 for mp3
		{ ; } // NOPE!
	else // MP3!
	  {
	  return(true);
	  }
	}
    offset++;
    missed++;
    }
  return(false);
} /* Seal_isMPEG() */

/**************************************
 Seal_MPEGsign(): Sign a MPEG.
 Insert a MPEG signature.
 **************************************/
sealfield *	Seal_MPEGsign	(sealfield *Args, mmapfile *MmapIn)
{
  const char *fname;
  sealfield *rec; // SEAL record
  char *Opt;
  mmapfile *MmapOut;
  size_t InsertOffset=0;

  if (!Seal_isMPEG(MmapIn)) { return(Args); } // should never happen

  fname = SealGetText(Args,"@FilenameOut");
  if (!fname || !fname[0] || !MmapIn) { return(Args); } // not signing

  Args = _SealWalkMPEG(Args,MmapIn);
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
	// MPEG doesn't support true appending.
	Args = SealAddText(Args,"b",",s~s+3"); // +3 for '"/>'
	//fprintf(stderr," ERROR: This format (MPEG) does not support appending. Skipping.\n");
	}

  // Get the record
  Args = SealRecord(Args); // get placeholder

  // Create the block
  Args = SealSetBin(Args,"@BLOCK",4,(const byte*)"\x00\x00\x00\x00"); // for safety, pad.

  // Make '@s' relative to block
  rec = SealSearch(Args,"@BLOCK");
  SealIncIindex(Args, "@s", 0, rec->ValueLen);
  SealIncIindex(Args, "@s", 1, rec->ValueLen);
 
  // Add record
  rec = SealSearch(Args,"@record");
  Args = SealAddBin(Args,"@BLOCK",rec->ValueLen,rec->Value);
  Args = SealAddText(Args,"@BLOCK","\n");

  Args = SealAddBin(Args,"@BLOCK",4,(const byte*)"\x00\x00\x00\x00"); // for safety, pad.
  SealSetType(Args,"@BLOCK",'x');
 
  MmapOut = SealInsert(Args,MmapIn,InsertOffset);
  if (MmapOut)
    {
    // Sign it!
    SealSign(Args,MmapOut);
    MmapFree(MmapOut);
    }
  
  return(Args);
} /* Seal_MPEGsign() */

/**************************************
 Seal_MPEG(): Process a MPEG.
 Reads every seal signature.
 If signing, add the signature before the IEND tag.
 **************************************/
sealfield *	Seal_MPEG	(sealfield *Args, mmapfile *Mmap)
{
  sealfield *a;

  // Make sure it's a MPEG.
  a = _SealWalkMPEG(Args,Mmap);
  if (!a) { return(Args); }
  Args = a;

  /*****
   Sign as needed
   *****/
  Args = Seal_MPEGsign(Args,Mmap); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_MPEG() */

