/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling BMFF files.
 BMFF includes HEIF, HEIC, AVIF, MP4

 Terminology: Every block is a "atom".

 This is a really simple file format (with caveats):
   4 byte: length in big endian.
   4 byte: Four Character Code (FourCC) for the atom type.
   length bytes: the data

 The caveats:

   - First FourCC is "ftyp". This identifies the file type and
     any compatible formats. E.g., "heic" is usually compatible with mif1.

   - Length includes itself and the FourCC!
     The minimum length is "8".

   - If the length is "1", then it's a special case.
     It means the length is longer than 32 bits.
     Following the FourCC is a 64-bit (8 byte) length.

     WARNING: When inserting a SEAL record, check if the length goes from
     32 to 64 bits!  This will break any previous signatures!

     In reality, I've never see a BMFF that required 64-bits. I've seen
     test files, but never actual files. The reason: 32-bits means 4 gigs.
     Files larger than 2 gigs often have trouble with applications. Due to
     signed int64 overflow. Or 4 gigs because they are not really able to
     handle more than 4 gigs.
       On 32-bit systems, size_t is 32-bits. So they can't handle 4 gigs.
       On 64-bit systems, size_t is 64-bits. But applications typically choke
       long before they reach that limit.

   - BMFF doesn't have a sense of local or global!
     Atoms may reference other atoms.
     E.g., MP4 uses some atoms to identify the CODEC, some for identifying
     data positions, and some for cross-indexing. This mmeans they are "global."
     However, settings for specific tracks are "local."
     A track can have it's own metadata, but the track settings impact the
     global playback.

     This means, we don't know the scope of the specific atom without
     knowing how to decode the entire nested structure.
     And "decode" is more than just walking the nested atoms! It means
     understanding the purpose! That's beyond the scope of SEAL.

   - EXIF and XMP may be nested anywhere in the file!
     In the top-level 'meta' atom.
     In the each nested track atom.
     In the "everything thrown together" 'mdat' atom.
     However, SEAL only processes them if they are top-level atom.
     Why? Because we don't know the scope of a nested atom!

   - Why bother with simple atoms?
     MP4 can store a moov:meta:ilst that contains a list of fields and
     a separate list of values!

     HEIC uses iloc and iinf together to store metadata, and these atoms
     are not nested!

     Some HEIC atoms use a 'version' code to identify 32-bit vs 64-bit.
     Other HEIC atoms use diffent atoms! (stco vs co64).
     I.e., there is zero consistency and most atoms are special cases.

  - Assuming you know the specific atom details and SEAL is inserted into
    a nested atom. It's not as simple as inserting it. Each atom has the
    length of it and all nested atoms. So modifying /meta/iprp/ipco
    requires updating the lengths for ipco, iprp, and meta.
    (Only the top-level atoms are not constrained by a global size.)

    Worse: Some atoms have absolute pointers into the mdat atom. So all of
    those need to be updated.

    More worse: You can't append signatures when the lengths of every parent
    atom keep changing. (Each change breaks the previous signature.)
    Or, you need a really complex exclusion list (b=....) that could permit
    unauthorized alterations.

 SEAL should know about the container, but not the arbitrary atoms within
 each container. Thus, SEAL can only sign top-level atoms.

 Fortunately: Unknown atoms are ignored by processing software!

 A SEAL record can exist:
   - Top-level FourCC "SEAL".
     The value of the SEAL atom is a "<seal .../>" record.

   - Top-level FourCC "Exif". (Contains EXIF)
     HEIC/AVIF: Usually these are not top-level. They are iinf:infe:Exif
     with data in iloc.
     Assume they are global and not relative.

   - Top-level FourCC "mime". (Contains XMP)
     HEIC/AVIF: Usually these are not top-level. They are iinf:infe:mime
     with data in iloc.
     Assume they are global and not relative.

   - Top-level FourCC "data". (nested atoms with artist, album, etc. data)
     MP4: Usually moov:meta:ilst
     Assume they are global and not relative. However, I've seen some
     videos where different tracks have different attributions!

 For signing?
 Keep it simple. Append the SEAL record at the end of the file.
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
 **************************************/

/**************************************
 **************************************/
struct
  {
  const char *name;
  byte type; // 'r' for recurse, 's' for scan, 'i' for iinf, 'e' for exif
  } BMFFatoms[] =
  {
#if 0
    // recursive
    {"dinf",'r'}, // Data Info
    {"edts",'r'}, // Edits
    {"ftyp",'r'}, // Header file type
    {"ilst",'r'}, // Item list
    {"iprp",'r'}, // Item properties (HEIC)
    {"iref",'r'}, // Item Reference"
    {"hoov",'r'}, // Apple HEIV movie stream, embedded in mdat
    {"mdia",'r'}, // Media
    {"meta",'r'}, // Meta Data
    {"minf",'r'}, // Media Info
    {"moov",'r'}, // Movie
    {"stbl",'r'}, // Sample Table
    {"trak",'r'}, // Track Definition
    {"udta",'r'}, // User Data
    {"ipco",'r'}, // Item Property Container (HEIC)
    {"iprp",'r'}, // Item properties (HEIC)
    {"gmhd",'r'}, // GenMedia Header
    // arrays of atoms
    {"iinf",'i'}, // item info (HEIC); array
    {"iloc",'l'}, // item location (HEIC); array
    // May contain SEAL record
#endif
    {"SEAL",'s'},
    {"name",'s'},
    {"mdta",'s'}, // metadata
    {"keys",'s'}, // item keys
    {"mime",'s'}, // XMP
    {"xml ",'s'}, // XMP
    {"XMP_",'s'}, // XMP
    {"Exif",'e'}, // EXIF
    {NULL,0} // END
  };

/**************************************
 _BMFFwalk(): Given a BMFF, walk the structures.
 Evaluate any SEAL or text chunks.
   Data and DataLen are for the current chunk.
   Pos is the absolute start of the chunk relative to the file.
   Mmap is the absolute start of the file.
   Uses '@BMFF' to track the nested path.
 Data and Pos may change during recursion, but Mmap is always source file.
 NOTE: This is recursive! (Recursion is disabled for now.)
 **************************************/
sealfield *	_BMFFwalk	(sealfield *Args, size_t DataStart, size_t DataEnd, unsigned int Depth, mmapfile *Mmap)
{
  sealfield *bmff;
  size_t AtomLen, AtomHeader;
  int a;

  bmff = SealSearch(Args,"@BMFF");
  while(DataStart+8 <= DataEnd)
    {
    AtomLen = readbe32(Mmap->mem + DataStart);
    if (DataStart+AtomLen > DataEnd) { break; } // overflow
    if (AtomLen==0) { DataStart+=4; continue; } // null padding
    AtomHeader=4;

    // Check for extended length
    if (AtomLen == 1)
	{
	if (DataStart + 16 > DataEnd) { break; } // overflow
	AtomLen = readbe64(Mmap->mem + DataStart + 8);
	AtomHeader+=8;
	}

    // Track the tag
    bmff = SealSearch(Args,"@BMFF");
    if (!bmff || (bmff->ValueLen < 5+Depth*5))
	{
	Args = SealAddTextLen(Args,"@BMFF",1,"/");
	Args = SealAddBin(Args,"@BMFF",4,Mmap->mem+DataStart+4);
	}
    else
	{
	// e.g. "moov", "moovmeta", "moovmetaexif", etc.
	bmff->ValueLen -= 4;
	Args = SealAddBin(Args,"@BMFF",4,Mmap->mem+DataStart+4);
	}
    bmff = SealSearch(Args,"@BMFF");
    AtomHeader+=4;

    // Look for recursive structures
    //DEBUGPRINT("MBFF: %.*s  [%ld]",(int)bmff->ValueLen,bmff->Value,(long)AtomLen);
    for(a=0; BMFFatoms[a].type; a++)
	{
	if (memcmp(BMFFatoms[a].name,Mmap->mem+DataStart+4,4)) { continue; }
#if 0
	else if (BMFFatoms[a].type=='r') // RECURSE!
	  {
	  // RECURSE!
	  Args = _BMFFwalk(Args, DataStart+AtomHeader, DataStart+AtomLen, Depth+1, Mmap);
	  }
	else if (BMFFatoms[a].type=='i') // iinf array of items
	  {
	  uint32_t Version, Count, c;
	  if (AtomLen < 18) { break; } // overflow
	  Version = readbe16(Mmap->mem+DataStart+AtomHeader+0);
	  if (Version==0) { Count = readbe16(Mmap->mem+DataStart+AtomHeader+4); }
	  else { Count = readbe32(Mmap->mem+DataStart+AtomHeader+4); }
	  }
	else if (BMFFatoms[a].type=='l') // iloc array of items
	  {
	  uint32_t Version, Count, c;
	  if (AtomLen < 18) { break; } // overflow
	  Version = Mmap->mem[DataStart+AtomHeader];
	  if (Version < 2) { Count = readbe16(Mmap->mem+DataStart+AtomHeader+6); }
	  else { Count = readbe32(Mmap->mem+DataStart+AtomHeader+6); }
	  }
#endif
	else if (BMFFatoms[a].type=='s') // search for SEAL!
	  {
	  Args = SealVerifyBlock(Args, DataStart, DataStart+AtomLen, Mmap, NULL);
	  }
	else if (BMFFatoms[a].type=='e') // search EXIF for SEAL!
	  {
	  // Process possible EXIF for SEAL record.
	  Args = Seal_Exif(Args,Mmap,DataStart,AtomLen);
	  }
	break;
	}

    // Continue
    DataStart += AtomLen;
    }

  if (bmff && (bmff->ValueLen >= 5)) { bmff->ValueLen -= 5; }
  return(Args);
} /* _BMFFwalk() */

#pragma GCC visibility pop

/**************************************
 Seal_isBMFF(): Is this file a BMFF?
 Returns: true or false.
 **************************************/
bool	Seal_isBMFF	(mmapfile *Mmap)
{
  if (!Mmap || (Mmap->memsize < 16)) { return(false); }

  /* header begins with "length ftyp" */
  if (memcmp(Mmap->mem+4,"ftyp",4)) { return(false); } /* not a BMFF! */
  return(true);
} /* Seal_isBMFF() */

/**************************************
 Seal_BMFFsign(): Sign a BMFF.
 Insert a BMFF signature.
 **************************************/
sealfield *	Seal_BMFFsign	(sealfield *Args, mmapfile *MmapIn)
{
  /*****
   Signing a BMFF is really easy:
   Add the signed block to the end.
   The only hard part is computing the encoded integers for tag and length.
   *****/
  const char *fname;
  char *Opt;
  mmapfile *MmapOut;
  sealfield *rec;

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
	// Skip the PNG checksum and finalize to the end of file ("f")
	Args = SealAddText(Args,"b",",s~f");
	}
  else
	{
	Args = SealAddText(Args,"b",",s~s+3"); // +3 for '"/>'
	}

  // Get the record
  Args = SealRecord(Args); // get placeholder '@record'
  rec = SealSearch(Args,"@record");

  // Create the block
  Args = SealSetTextLen(Args,"@BLOCK",8,"....SEAL"); // placeholder for length + FourCC
  // Make '@s' relative to block
  SealIncIindex(Args, "@s", 0, SealGetSize(Args,"@BLOCK"));
  SealIncIindex(Args, "@s", 1, SealGetSize(Args,"@BLOCK"));
  // Add record
  Args = SealAddBin(Args,"@BLOCK",rec->ValueLen,rec->Value);
  SealSetType(Args,"@BLOCK",'x');
  // Set the length
  rec = SealSearch(Args,"@BLOCK");
  writebe32(rec->Value,rec->ValueLen);
  
  MmapOut = SealInsert(Args,MmapIn,MmapIn->memsize);
  if (MmapOut)
    {
    // Sign it!
    SealSign(Args,MmapOut,NULL);
    MmapFree(MmapOut);
    }
  
  return(Args);
} /* Seal_BMFFsign() */

/**************************************
 Seal_BMFF(): Process a BMFF.
 Reads every seal signature.
 If signing, add the signature before the IEND tag.
 **************************************/
sealfield *	Seal_BMFF	(sealfield *Args, mmapfile *Mmap)
{
  // Make sure it's a BMFF.
  if (!Seal_isBMFF(Mmap)) { return(Args); }

  Args = _BMFFwalk(Args, 0, Mmap->memsize, 0, Mmap);
  Args = SealDel(Args,"@BMFF"); // no longer needed

  /*****
   Sign as needed
   *****/
  Args = Seal_BMFFsign(Args,Mmap); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_BMFF() */

