/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling PPM/PBM/PGM files.
 (Part of the Netpbm suite of image tools.)

 This is a really basic file format.
 (Hard to get much simpler.)

 Every file begines with:
   Type of file
	P1 :: Text PBM (bitmap): all numbers are 0 or 1
	P2 :: Text PGM (graymap): 1 color channel
	P3 :: Text PPM (pixelmap): 3 color channels
	P4 :: Binary PBM: One bit per pixel, BIG_ENDIAN
	P5 :: Binary PGM: Binary data
	P6 :: Binary PPM: Binary data
	P7 :: PAM (anymap), header defines contents
   Width, Height, Max Value
   There is exactly one whitespace after type, width, height, and max value.
   Then comes the data.

 Type, Width, Height, and MaxValue are separated by whitespace.
 (Typically \n, but can be spaces.)

 If 256 <= MaxValue < 65536, then there are two bytes per color channel.
 The data should contain enought values to fill out the file type.

 Now for the fun part:
 Any "#" appearing before the space before the data denotes a comment.
 Comments end with a newline \n.
 E.g.:
   P7
   #comment
   123 # the width
   456 # the height
   #comment
   255
   data

 SEAL can be stored in a comment!

 Netpbm says that no line should be longer than 70 characters.
 However, when reading comments, they just skip from # to \n.
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
 _SealWalkPPM(): Scan the header and find the offset to insert.
 Returns:
   if Args is set: Offset is in '@InsertOffset'
   if Args is NULL: returns (sealfield*)1 if PPM, or NULL if not.
 offset, or 0 on error.
 **************************************/
sealfield *	_SealWalkPPM	(sealfield *Args, mmapfile *Mmap)
{
  int f;
  size_t i,iend;

  if (!Mmap || (Mmap->memsize < 16)) { return(NULL); }

  /* header begins with P1, P2, ... P7 */
  if ((Mmap->mem[0]=='P') &&
      (Mmap->mem[1]>='1') && (Mmap->mem[1]<='7') &&
      (isspace(Mmap->mem[3]) || (Mmap->mem[3]=='#'))
     )
	{ return(NULL); }

  /* Check for 3 fields: width, height, max value */
  i=3;
  for(f=0; f < 3; f++)
    {
    while((i < Mmap->memsize) && (Mmap->mem[i]=='#')) // comment!
	{
	// Skip the comment
	iend=i;
	while((iend < Mmap->memsize) && (Mmap->mem[iend] != '\n')) { iend++; }
	if (iend >= Mmap->memsize) { return(NULL); }
	if (Args)
	  {
	  Args = SealVerifyBlock(Args, i, iend, Mmap, NULL);
	  }
	i=iend+1;
	}

    // Insert as last possible comment!
    if ((f==2) && Args) { Args=SealSetIindex(Args,"@InsertOffset",0,i); }

    // Read digit
    if ((i >= Mmap->memsize) || !isdigit(Mmap->mem[i])) { return(NULL); }
    while((i < Mmap->memsize) && isdigit(Mmap->mem[i])) { i++; }
    if (i >= Mmap->memsize) { return(NULL); }
    // Followed by space or "#"
    if (isspace(Mmap->mem[i])) { i++; }
    else if ((f < 2) && (Mmap->mem[i] == '3')) { ; } // another comment!
    else { return(NULL); }
    }

  if (Args) { return(Args); }
  return((sealfield*)1);
} /* _SealWalkPPM() */

#pragma GCC visibility pop

/**************************************
 Seal_isPPM(): Is this file a PPM?
 Returns: true or false.
 **************************************/
bool	Seal_isPPM	(mmapfile *Mmap)
{
  if (_SealWalkPPM(NULL,Mmap) == NULL) { return(false); }
  return(true);
} /* Seal_isPPM() */

/**************************************
 Seal_PPMsign(): Sign a PPM.
 Insert a PPM signature.
 **************************************/
sealfield *	Seal_PPMsign	(sealfield *Args, mmapfile *MmapIn)
{
  /*****
   Signing a PPM is really easy:
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
	// PPM doesn't support true appending.
	Args = SealAddText(Args,"b",",s~s+3"); // +3 for '"/>'
	//fprintf(stderr," ERROR: This format (PPM) does not support appending. Skipping.\n");
	}

  // Get the record
  Args = SealRecord(Args); // get placeholder

  // Create the block
  rec = SealSearch(Args,"@record");
  Args = SealSetText(Args,"@BLOCK","# "); // encode "SEAL" tag
  // Make '@s' relative to block
  SealIncIindex(Args, "@s", 0, 2);
  SealIncIindex(Args, "@s", 1, 2);
  // Add record
  Args = SealAddBin(Args,"@BLOCK",rec->ValueLen,rec->Value);
  Args = SealAddText(Args,"@BLOCK","\n");
  SealSetType(Args,"@BLOCK",'x');
 
  MmapOut = SealInsert(Args,MmapIn,InsertOffset);
  if (MmapOut)
    {
    // Sign it!
    SealSign(Args,MmapOut,NULL);
    MmapFree(MmapOut);
    }
  
  return(Args);
} /* Seal_PPMsign() */

/**************************************
 Seal_PPM(): Process a PPM.
 Reads every seal signature.
 If signing, add the signature before the IEND tag.
 **************************************/
sealfield *	Seal_PPM	(sealfield *Args, mmapfile *Mmap)
{
  sealfield *a;

  // Make sure it's a PPM.
  a = _SealWalkPPM(Args,Mmap);
  if (!a) { return(Args); }
  Args = a;

  /*****
   Sign as needed
   *****/
  Args = Seal_PPMsign(Args,Mmap); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_PPM() */

