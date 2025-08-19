/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling AAC (audio and video) files.

 AAC was designed as a replacement for MPEG, but it's still horribly complex.

 Fortunately, we can use the same trick for signing MPEG/MP3!

 1. Every AAC frame begins with 0xfff0 or 0xfff1.

 2. Computing the frame length is complicated, but finding the next
    start of frame is easy: 0xfff0 or 0xfff1.

 3. Any non-frame data after the previous frame and before the next frame 
    is ignored.

 The SEAL record can be inserted between any frame!
 You just have to find out where the frame is located. That's the hard part.
 (Unless you just append it to the end of the AAC! FTW!)

 =====
 Decoding the frame header is detailed in ExifTool AAC.pm:
 # format of frame header (7 bytes):
 # SSSS SSSS SSSS ILLC PPRR RRpC CCoh csff ffff ffff fffb bbbb bbbb bbNN
 # 1111 1111 1111 0001 0110 0000 0100 0000 0000 0101 0101 1111 1111 1100 (eg.)
 #  S = sync word                o = original/copy
 #  I = ID                       h = home
 #  L = layer (00)               c = copyright ID
 #  C = CRC absent               s = copyright start
 #  P = profile object type      f = frame length
 #  R = sampling rate index      b = buffer fullness
 #  p = private                  N = number of raw data blocks in frame
 #  C = channel configuration
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
 _SealIsAACframe(): Is this an AAC frame?
 There must be 7 bytes available.
 Returns: frame length or 0 if not a frame.
 **************************************/
uint16_t	_SealIsAACframe	(byte *Data)
{
  uint16_t u16;
  /*****
   Per ExifTool AAC.pm, check reserved bits.

   # format of frame header (7 bytes):
   byte 0     |1        |2        |3        |4        |5        |6
   # SSSS SSSS SSSS ILLC PPRR RRpC CCoh csff ffff ffff fffb bbbb bbbb bbNN
   # 1111 1111 1111 0001 0110 0000 0100 0000 0000 0101 0101 1111 1111 1100 (eg.)
   #  S = sync word                o = original/copy
   #  I = ID                       h = home
   #  L = layer (00)               c = copyright ID
   #  C = CRC absent               s = copyright start
   #  P = profile object type      f = frame length
   #  R = sampling rate index      b = buffer fullness
   #  p = private                  N = number of raw data blocks in frame
   #  C = channel configuration

   P cannot be 3  (reserved profile type)
   R cannot be > 12  (sampling frequency index)
   f cannot be < 7  (frame length)
  
   $raf->Read($buff, 7) == 7 or return 0;
   return 0 unless $buff =~ /^\xff[\xf0\xf1]/;
   my @t = unpack('NnC', $buff);
   return 0 if (($t[0] >> 16) & 0x03) == 3; # (reserved profile type)
   return 0 if (($t[0] >> 12) & 0x0f) > 12; # validate sampling frequency index
   my $len = (($t[0] << 11) & 0x1800) | (($t[1] >> 5) & 0x07ff);
   return 0 if $len < 7;
   *****/

  // Check sync word
  u16 = readbe16(Data+0);
  switch(u16)
	{
	case 0xfff0: // no CRC
	case 0xfff1: // has CRC
	  break;
	default:
	  return(0);
	}

  u16 = readbe16(Data+2);
  if ((u16 & 0xc000) == 0xc000) { return(0); } // P cannot be 3
  if ((u16 & 0x3c00) > (12<<10)) { return(0); } // R cannot be > 12

  // Get the length
  u16 = (Data[3]&0x03);
  u16 = (u16<<8) | Data[4];
  u16 = (u16<<3) | ((Data[5]>>5)&0x07);
  if (u16 < 7) { return(0); }
  return(u16);
} /* _SealIsAACframe() */

/**************************************
 _SealWalkAAC(): Scan the AAC and find the offset to insert.
 Returns:
   Offset is in '@InsertOffset'
 offset, or 0 on error.
 **************************************/
sealfield *	_SealWalkAAC	(sealfield *Args, mmapfile *Mmap)
{
  size_t offset, scanStart;
  uint16_t u16;

  // Check for AAC; permit up to 1K of garbage
  scanStart=offset=0;
  while(offset+7 <= Mmap->memsize)
    {
    u16 = _SealIsAACframe(Mmap->mem+offset);
    if (u16==0) { offset++; } // skip non-frame
    else
	{
	// verify data between frames
	if (scanStart < offset) { Args = SealVerifyBlock(Args, scanStart, offset, Mmap, NULL); }
	offset += u16;
	scanStart = offset;
	}
    }
  // Scan to end of file
  if (scanStart < Mmap->memsize) { Args = SealVerifyBlock(Args, scanStart, Mmap->memsize, Mmap, NULL); }
  // Truncated file? Insert after the last frame!
  Args = SealSetIindex(Args,"@InsertOffset",0,(offset > Mmap->memsize) ? offset : Mmap->memsize);
  return(Args);
} /* _SealWalkAAC() */

#pragma GCC visibility pop

/**************************************
 Seal_isAAC(): Is this file a AAC?
 Returns: true or false.
 **************************************/
bool	Seal_isAAC	(mmapfile *Mmap)
{
  if (!Mmap || (Mmap->memsize < 40)) { return(false); } // too small
  // Must begin with a frame
  if (_SealIsAACframe(Mmap->mem) > 0) { return(true); } // valid frame
  return(false);
} /* Seal_isAAC() */

/**************************************
 Seal_AACsign(): Sign a AAC.
 Insert a AAC signature.
 **************************************/
sealfield *	Seal_AACsign	(sealfield *Args, mmapfile *MmapIn)
{
  const char *fname;
  sealfield *rec; // SEAL record
  char *Opt;
  mmapfile *MmapOut;
  size_t InsertOffset=0;

  if (!Seal_isAAC(MmapIn)) { return(Args); } // should never happen

  fname = SealGetText(Args,"@FilenameOut");
  if (!fname || !fname[0] || !MmapIn) { return(Args); } // not signing

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
	// AAC doesn't support true appending.
	Args = SealAddText(Args,"b",",s~s+3"); // +3 for '"/>'
	//fprintf(stderr," ERROR: This format (AAC) does not support appending. Skipping.\n");
	}

  // Get the record
  Args = SealRecord(Args); // get placeholder

  // Create the block
  Args = SealSetBin(Args,"@BLOCK",1,(const byte*)"\x00"); // for safety, pad.

  // Make '@s' relative to block
  rec = SealSearch(Args,"@BLOCK");
  SealIncIindex(Args, "@s", 0, rec->ValueLen);
  SealIncIindex(Args, "@s", 1, rec->ValueLen);
 
  // Add record
  rec = SealSearch(Args,"@record");
  Args = SealAddBin(Args,"@BLOCK",rec->ValueLen,rec->Value);
  Args = SealAddText(Args,"@BLOCK","\n");

  Args = SealAddBin(Args,"@BLOCK",1,(const byte*)"\x00"); // for safety, pad.
  SealSetType(Args,"@BLOCK",'x');
 
  MmapOut = SealInsert(Args,MmapIn,InsertOffset);
  if (MmapOut)
    {
    // Sign it!
    SealSign(Args,MmapOut,NULL);
    MmapFree(MmapOut);
    }
  
  return(Args);
} /* Seal_AACsign() */

/**************************************
 Seal_AAC(): Process a AAC.
 Reads every seal signature.
 If signing, add the signature before the IEND tag.
 **************************************/
sealfield *	Seal_AAC	(sealfield *Args, mmapfile *Mmap)
{
  sealfield *a;

  // Make sure it's a AAC.
  a = _SealWalkAAC(Args,Mmap);
  if (!a) { return(Args); }
  Args = a;

  /*****
   Sign as needed
   *****/
  Args = Seal_AACsign(Args,Mmap); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_AAC() */

