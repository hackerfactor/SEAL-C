/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling zip files.

 We have a few options for storing the SEAL record in zip, and none are ideal.

 Option 1: Include a "seal.sig" file (like a sidecar) in the zip archive.
   Pro: Easy to do. (There's a libzip library function for adding it.)
   Con: Users will see an unexpected "seal.sig" file when they open the archive.
   We don't want to surprise anyone with an unexpected file.

 Option 2: Stuff the SEAL record in the zip archive's comment field.
   Pro: Easy to do. (There's a libzip library function for adding it.)
   Meh: Limited to 65K. (Unlikely to be a problem.)
   Con: Repurposes the comment for something other than a comment.
   Con: Someone using zipinfo or other tools to read the comment will see the SEAL record as a random text string.

 Option 3: Zip permits per-file extra attributes.
   We can stuff the SEAL in any of these and have it cover the entire archive.
   Pro: Easy to do. (There's a libzip library function for adding it.)
   Con: Repurposes the per-file attribute to span the entire archive.

 Option 4: Zip uses a bunch of 4-byte tags to denote different segments.
   Create my own unique 4-byte tag.
   Pro: Flexible.
   Con: Non-standard. Won't cause problems, but won't be retained.
   If this could be standardized, then this would be an ideal solution.

 Option 5: Have the Zip folks add in a place for storing this.
   They already have a place for storing X.509 certs, but that is very specific.
   Con: We don't want to repurpose the X.509 area because that could cause problems.
   Con: There are some numeric codes where you can store data. However, they are not standardized.
   (The folks at libzip discouraged this.)
   If this could be standardized, then this would be an ideal solution.

 Neal chatted with the folks behind libzip.
   - They agreed that options 1 and 3 aren't great.
   - Option 4 and 5 may take years to become standardized for zip use.
   - They recommended Option 2, noting that today, almost nobody uses zip archive comments.

 Thus, option 2 wins: We stuff the zip record in the archive comment.
 (NOT in the per-file comment; this goes in the overall archive comment.)

 =====================
 Zip files are parsed starting at the end of the file.
 For detauis, see: https://en.wikipedia.org/wiki/ZIP_(file_format)

   - Search backwards from the end until you find the end of the central directory.
     The CD ends with a end of central directory (EOCD): 50 4b 05 06
     This is followed by the number of disks, records, etc. AND the comment.
     This is the comment that can contain the SEAL record.
     (Validate the comment length, make sure there are no overflows.)

   - Before the EOCD is the central directory file header (CDFH): 50 4b 01 02
     Make sure it exists and looks valid.
     There should be one CDFH per file (and the EOCD says how many files).
     Make sure they all exist.

   - Each record has the offset to the local file header; make sure it exists.
     The local file header begins with 50 4b 03 04.

   - The furthest back local file header denotes the start of the zip file.

 Zip files can be embedded in another file format.
 For example, they are sometimes seen stuffed in unused space within a JPEG:
      +-----------------------------+
      | Start of JPEG               |
      +-----------------------------+
      | Zip3 stuffed in a JPEG      |
      +-----------------------------+
      | More JPEG                   |
      +-----------------------------+
      | Zip2 stuffed in a JPEG      |
      +-----------------------------+
      | More JPEG                   |
      +-----------------------------+
      | Zip1 stuffed at end of JPEG |
      +-----------------------------+

 Each zip file is self-contained and independent.
 SEAL uses a range: F~f to denote the start of file (F) and end of file (f).
   f = Where the comment field for the EOCD ends.
   F = Where the furthest back local file header begins.

 With many file formats, you can append data.
 That means SEAL signatures can be followed by more data and another signature.
 Zip lists all files first and then the signature in the archive comment.
 This means that any appended files to the zip will break the previous signatures.
 Thus, zip does not support appending.
 When signing, the range should always be "F~S,s~f"
   (Start of zip file to start of signature, then end of signature to end of file.)

 With Zip we can only sign the file if the end of the EOCD comment is the same as
 the end of the file.
 Why? Because we cannot make assumptions about the containing file.
 We cannot append a comment without potentially breaking the containing file format.
 E.g., if we insert a SEAL signature into Zip2 (above), then it can break the JPEG format.
 Before signing, be absolutely sure that we are allowed to sign.

 For signing, there may already be a comment!
 If there is, then add a newline at the end (if there isn't already one) and then
 insert the SEAL record.

 NOTE: Zip is such an easy file format, you should never need libzip.
 ************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "seal.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"
#include "files.hpp"
#include "formats.hpp"

typedef struct {
  uint64_t Start,End; // inclusive start, exclusive end range inside Mmap->mem
  uint32_t commentoff, commentlen; // EOCD comment position (absolute offset in Mmap->mem)
  mmapfile *Mmap;
  bool IsSigned;
  } ziprange;

#define LEREAD16(x)	(uint16_t)( ((x)[1]<<8) | (x)[0] )
#define LEREAD32(x)	(uint32_t)( ((x)[3]<<24) | ((x)[2]<<16) | ((x)[1]<<8) | (x)[0] )

/**************************************
 _Seal_ZipFind(): Given a range, find the last zip in the file.
 This scans backwards, starting from the last Start.
 To initialize: Start and End should be Mmap->memsize-1.

 NOTE: This skips nested zip files: zip(zip(zip))
 It only finds sequential zip files. zip...zip...zip

 Returns:
   true if found, false if not.
   Updates offset range for the found zip file.
 **************************************/
bool	_Seal_ZipFind	(ziprange *z)
{
  uint64_t eocd,cdfh,cdoffset,cdsize,n;

rescan:
  // Idiot checking
  if (z->Start > z->Mmap->memsize) { return(false); }
  // Make sure there is minimal room
  // Why 22 bytes? Minimum EOCD 22 bytes. (Shortest zip is an empty zip with just an EOCD.)
  if (z->Start < 22) { return(false); }

  // Reset range
  z->End = z->Start;

  // Find the End of central directory record (EOCD)
  eocd = z->End;
  for(n = z->End-21; n > 0; n--)
    {
    if (!memcmp(z->Mmap->mem+n-1,"\x50\x4b\x05\x06",4)) { eocd = n-1; break; }
    }
  if (eocd == z->End) { return(false); } // no EOCD found

  /*****
   Process the EOCD!
   End of central directory record (EOCD)
   off  len purpose
   -----------------------
    0   4   Magic number. Must be 50 4B 05 06.
    4   2   Number of this disk (or FF FF for ZIP64).
    6   2   Disk where central directory starts (or FF FF for ZIP64).
    8   2   Number of central directory records on this disk (or FF FF for ZIP64).
   10   2   Total number of central directory records (or FF FF for ZIP64).
   12   4   Size of central directory in bytes (or FF FF FF FF for ZIP64).
   16   4   Offset of start of central directory, relative to start of archive (or FF FF FF FF for ZIP64).
   20   2   Comment length (n).
   22  	n   Comment.

   Finding the end of the zip is easy. (eocd offset + 22 + comment length)
   Finding the start of the zip requires finding the furthest back record.
   The furthest back should be a local file header (magic: 504b0304).

   How to find the start of the zip:
   The EOCD contains everything we need!
     eocd+12 is the size of the central directory.
     eocd+16 is the offset from the start of the zip to the central directory.
   So:
     Start = eocd - size of central directory - offset to the central directory


   That's great for regular zip, but what about zip64?
   If you see all of the 0xff values, then check at eocd-20 for the eocd64_locator!
    0   4   Magic number. Must be 50 4B 06 07.
    4   4   Disk with eocd record
    8   8   Offset to eocd64 directory (eocd64offset; relative to start of file)
   16   4   Total number of disks
   (total header: 20)

   Then check for the eocd64:
     eocd64 position = eocd64_locator - 56 = eocd - 20 - 56.
    0   4   Magic number. Must be 50 4B 06 06.
    4   8   Size of central directory
   12   2   Version created
   14   2   Version minimum needed
   16   4   Disk number
   20   4   Disk with central directory
   24   8   Number of central directory records in this zip
   32   8   Total Number of central directory records
   40   8   Size of central directory
   48   8   Offset to central directory (relative to start of file)
   (total header: 56)

   Where is the end? It's still eocd offset + 22 + comment length
   Where is the start? It's eocd64 offset - offset to eocd64!
   *****/

#if 0
  // Debugging: Print the EOCD
  DEBUGPRINT("EOCD at 0x%lx",(ulong)eocd);
  DEBUGPRINT("  Disk num:       %u",LEREAD16(z->Mmap->mem + eocd+4));
  DEBUGPRINT("  Disk CD start:  %u",LEREAD16(z->Mmap->mem + eocd+6));
  DEBUGPRINT("  CD recs here:   %u",LEREAD16(z->Mmap->mem + eocd+8));
  DEBUGPRINT("  Total CD recs:  %u",LEREAD16(z->Mmap->mem + eocd+10));
  DEBUGPRINT("  CD Size:        %u",LEREAD32(z->Mmap->mem + eocd+12));
  DEBUGPRINT("  CD Offset:      0x%x",LEREAD32(z->Mmap->mem + eocd+16)); // absolute offset
  DEBUGPRINT("  Comment Size:   %u",LEREAD16(z->Mmap->mem + eocd+20));
#endif

  // Determine length of the EOCD
  z->commentoff = eocd + 22;
  z->commentlen = LEREAD16(z->Mmap->mem + eocd+20);
  // Idiot checking
  if (z->commentoff+z->commentlen > z->End)
    {
    // Corrupted comment! (But continue scanning.)
    // i.e., corrupted, but not enough to outright fail.
    z->commentlen = z->End - z->commentoff;
    }
  z->End = z->commentoff + z->commentlen; // Found the new end of the zip!
  z->Start = eocd; // furthest known "go back"

  // Identify the start of the file
  // check for zip64
  if ((LEREAD32(z->Mmap->mem+eocd+8)==0xffffffff) &&
      (LEREAD32(z->Mmap->mem+eocd+12)==0xffffffff) &&
      (LEREAD32(z->Mmap->mem+eocd+16)==0xffffffff))
    {
    // It's zip64!
    uint64_t eocd64loc,eocd64,eocd64off;
    // Check for expected magics
    if ((eocd < 16+56) || // overflow
        memcmp(z->Mmap->mem+eocd-20,"\x50\x4b\x06\x07",4) || // corrupt
        memcmp(z->Mmap->mem+eocd-20-56,"\x50\x4b\x06\x06",4)) // corrupt
	{
	// Assume zip files overlap
	z->Start += 18;
	goto rescan;
	}
    eocd64loc = eocd-20;
    eocd64 = eocd64loc-56;
    eocd64off = LEREAD32(z->Mmap->mem+eocd64loc+12);
    eocd64off = (eocd64off << 32) | LEREAD32(z->Mmap->mem+eocd64loc+8);
    if (eocd64off > eocd64) // corrupt
	{
	// Assume zip files overlap
	z->Start += 18;
	goto rescan;
	}
    z->Start = eocd64 - eocd64off;
    }
  else
    {
    // It's regular zip!
    cdsize = LEREAD32(z->Mmap->mem + eocd+12); // how large is the total number of CDFH records?
    cdoffset = LEREAD32(z->Mmap->mem + eocd+16); // how large is the total number of CDFH records?
    if (cdsize+cdoffset > eocd) // corrupt!
      {
      // Assume zip files overlap
      z->Start += 18;
      goto rescan;
      }
    cdfh = eocd - cdsize;
    z->Start = cdfh - cdoffset;
    }
  //DEBUGPRINT("Zip found at: 0x%lx - 0x%lx",(ulong)z->Start,(ulong)z->End);

  return(true); // Found a zip!
} /* _Seal_ZipFind() */

/**************************************
 Seal_isZip(): Is this file a Zip?
 Returns: true or false.
 **************************************/
bool	Seal_isZip	(mmapfile *Mmap)
{
  ziprange z;

  memset(&z,0,sizeof(ziprange));
  z.Mmap = Mmap;
  z.Start = z.End = Mmap->memsize;

  if (_Seal_ZipFind(&z)) { return(true); }
  return(false); // if it is not a zip
} /* Seal_isZip() */

/**************************************
 Seal_Zipsign(): Sign a Zip.
 Insert a Zip signature.
 **************************************/
sealfield *	Seal_Zipsign	(sealfield *Args, ziprange *z)
{
  /*****
   Signing a Zip is really easy:
   Add the signed block to the end.
   The only hard part is computing the encoded integers for tag and length.
   *****/
  const char *fname;
  sealfield *rec; // SEAL record
  char *Opt;
  mmapfile *MmapOut=NULL;

  fname = SealGetText(Args,"@FilenameOut");
  if (!fname || !fname[0] || !z || !z->Mmap) { return(Args); } // not signing

  if (z->End != z->Mmap->memsize) // can only sign at the end of a zip
    {
    fprintf(stderr," ERROR: This format (Zip) does not support appending. Skipping.\n");
    return(Args);
    }

  Args = SealDel(Args,"@InsertOffset");

  // Set the range
  Opt = SealGetText(Args,"options"); // grab options list
  if (Opt && strstr(Opt,"append")) // if append
	{
	fprintf(stderr," ERROR: This format (Zip) does not support appending. Skipping.\n");
	return(Args);
	}

  /*****
   Determine the byte range for the digest.
   Zip doesn't support interlaced SEAL signatures, so appending won't work.
   Always sign the entire file, even if the user wanted to sign a smaller range.
   *****/
  Args = SealDel(Args,"b");
  Args = SealSetText(Args,"b","F~S,s~f");

  // Get the record
  Args = SealRecord(Args); // get placeholder

  // Create the block
  rec = SealSearch(Args,"@record");
  if ((z->commentlen > 0) && !strchr("\r\n",z->Mmap->mem[z->commentoff + z->commentlen-1]))
    {
    // If there is already a comment, make signature begin with a newline.
    Args = SealSetText(Args,"@BLOCK","\n");
    // Make '@s' relative to block
    SealIncIindex(Args, "@s", 0, 1);
    SealIncIindex(Args, "@s", 1, 1);
    }

  // Make sure the comment length is not too long
  if (z->commentlen + SealGetSize(Args,"@BLOCK") >= 0xffff)
	{
	if (z->commentlen > 0)
	  {
	  fprintf(stderr," ERROR: The existing comment + signature is too long for Zip files. Skipping.\n");
	  }
	else
	  {
	  fprintf(stderr," ERROR: The signature is too long for Zip files. Skipping.\n");
	  }
	return(Args);
	}

  // Add record
  Args = SealAddBin(Args,"@BLOCK",rec->ValueLen,rec->Value);
  Args = SealAddText(Args,"@BLOCK","\n");
  SealSetType(Args,"@BLOCK",'x');
 
  // Insert signature placeholder
  MmapOut = SealInsert(Args,z->Mmap,z->commentoff+z->commentlen);

  if (MmapOut)
    {
    // Fix zip comment length.
    z->commentlen += SealGetSize(Args,"@BLOCK");
    MmapOut->mem[z->commentoff-2] = z->commentlen & 0xff;
    MmapOut->mem[z->commentoff-1] = (z->commentlen >> 8) & 0xff;

    // Sign it!
    SealSign(Args,MmapOut,NULL);
    MmapFree(MmapOut);
    }
  
  return(Args);
} /* Seal_Zipsign() */

/**************************************
 Seal_Zip(): Process a Zip.
 Reads every seal signature.
 If signing, add the signature before the IEND tag.
 **************************************/
sealfield *	Seal_Zip	(sealfield *Args, mmapfile *Mmap)
{
  /*****
   There may be multiple zip files in the source file.
   Moreover, there may be a zip in a zip.
   If you find a zip, process it!
   NOTE: For signing, only sign the last zip.

   Use a uint64_t to track the file position.
   (It might be a big zip file.)
   Scan backwards from the end.
   Each time you find an EOCD, make sure it's a zip and then process it.
   Then, continue searching, starting from EOCD-1. This will catch any nested Zips.
   Stop scanning with your scanner says there are less than 98 bytes remaining.
   (Why 98? Minimum EOCD 22 bytes, CDFH 46 bytes, and Local file header 30 bytes.)
   *****/
  ziprange z;
  int ZipCount=0; // How many zips are embedded here?
  sealfield *ArgsLoc=NULL;
  bool HasSig=true;

  memset(&z,0,sizeof(ziprange));
  z.Mmap = Mmap;
  z.Start = z.End = Mmap->memsize;
  if (!_Seal_ZipFind(&z)) { return(Args); } // no zip found
  if ((z.Start==0) && (z.End==Mmap->memsize)) { HasSig=false; }

  // Verify every signature
  do	{
	ArgsLoc = SealClone(Args);
	// Remove any previous scan results
	ArgsLoc = SealDel(ArgsLoc,"@s");
	ArgsLoc = SealDel(ArgsLoc,"@digestrange");

	//DEBUGPRINT("Found zip: 0x%lx - 0x%lx, comment: @ 0x%lx len=%lu",(ulong)(z.Start),(ulong)(z.End),(ulong)(z.commentoff),(ulong)(z.commentlen));
	mmapfile Msub;
	Msub.mem = z.Mmap->mem + z.Start;
	Msub.memsize = z.End - z.Start;
	ZipCount++;

	// Record if this is an embedded file
	if ((z.Start != 0) || (z.End != z.Mmap->memsize))
	  {
	  char Label[25];
	  snprintf(Label,25,"embedded zip #%d",ZipCount);
	  ArgsLoc = SealSetText(ArgsLoc,"@embedname",Label);
	  ArgsLoc = SealSetU64index(ArgsLoc,"@embedbytes",0,z.Start);
	  ArgsLoc = SealSetU64index(ArgsLoc,"@embedbytes",1,z.End);
	  }

	// Verify!
	ArgsLoc = SealVerifyBlock(ArgsLoc, z.commentoff - z.Start, z.commentoff - z.Start + z.commentlen, &Msub, NULL);
	if (SealGetIindex(ArgsLoc,"@s",2)) // has signatures
	  {
	  HasSig=true;
	  Args = SealIncIindex(Args,"@s",2,1);
	  }

	// Clean up
	ArgsLoc = SealDel(ArgsLoc,"@embedname");
	ArgsLoc = SealDel(ArgsLoc,"@embedbytes");

	/*****
	 Sign as needed
	 *****/
	if (z.End == z.Mmap->memsize) // only sign the ending zip
	  {
	  Args = SealCopy2(Args,"@sflags",ArgsLoc,"@sflags"); // track finalizing
	  ArgsLoc = Seal_Zipsign(ArgsLoc,&z); // Add a signature as needed
	  if (SealSearch(ArgsLoc,"@s")) { HasSig=true; }
	  Args = SealCopy2(Args,"@s",ArgsLoc,"@s"); // track if it is signed
	  }
	SealFree(ArgsLoc);
	} while(_Seal_ZipFind(&z));

  if (!HasSig)
    {
    printf(" No SEAL signatures found.\n");
    }
  return(Args);
} /* Seal_Zip() */

