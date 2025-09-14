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
   Con: There are some numberic codes where you can store data. However, they are not standardized.
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
 Before signing, making absolutely sure that we are allowed to sign.

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

/**************************************
 Seal_isZip(): Is this file a Zip?
 Returns: true or false.
 **************************************/
bool	Seal_isZip	(mmapfile *Mmap)
{
  Mmap=Mmap; // hide unused compiler warning in this stub.

  // test for zip
  /* TBD */
  return(false); // if it is not a zip
  return(true); // if it is a zip
} /* Seal_isZip() */

/**************************************
 Seal_Zipsign(): Sign a Zip.
 Insert a Zip signature.
 **************************************/
sealfield *	Seal_Zipsign	(sealfield *Args, mmapfile *MmapIn)
{
  /*****
   Signing a Zip is really easy:
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
  Mmap=Mmap; // Hide compiler warnings in this stub.

  /*****
   Sign as needed
   *****/
  // Args = Seal_Zipsign(Args,Mmap,EOF_offset); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_Zip() */

