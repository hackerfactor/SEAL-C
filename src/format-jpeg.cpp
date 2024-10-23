/************************************************
 SEAL: implemented in C

 Functions for handling JPEG files.

 JPEG is a standard that likes to deviate from its standard.

 Each block begins with a two byte value, like: ffd8
 To identify a block, use:
   if (u16 & 0xffc0) == 0xffc0

 Some blocks have a length after them, but others don't.
   ffd8 :: start of image (no length)
     ffe0 - ffef :: app blocks, includes a 2-byte length
       The length includes itself! Never less than 2!
       The APP name is based on the last nibble:
       ffe0 = APP0, ffe5 = APP5, ffee = APP14, etc.
     ffda :: start of stream (forget nice blocks; just dump data after a short header)
   ffd9 :: end of image (no length)

 What if an app block needs to be longer than 2 bytes (65536 bytes)?
 Just have multple app blocks and they get contatenated.
 Some apps repeat the header in each continuation, while others don't.
 (See, the non-standard standard.)

 For the APP blocks, there should be:
   APPn :: 0xFFEn
   2 byte length, including itself
   Usually a name for the type of APP.
   APP data that matches the length-2

 There shouldn't be anything after the ffd9.
 Except that some blocks, like MakerNotes or APP2's MPF stuff data
 after the end of image because it's easier than writing multiple APP blocks.
 And some formats (ahem, Samsung) likes to include 'trailer' data in a non-JPEG format.

 When scanning for blocks, you cannot just look for the &ffc0 header.
 Why? Because some APP block, like EXIF, may include a JPEG as a thumbnail!
 So how do you scan?
   1. Read the tag. If it's not &ffc0, then skip a byte and try again.
      (It's okay to skip bytes in a jpeg.
   2. If the tag is ffd8 or ffd9, then don't read a length.
   3. For any other tag, read the 2-byte length.
      Assume anything inside the block is data for that block.

 For inserting SEAL:
   - Use APP8.  Why APP8? Nobody else uses it!
     Here's the APP block usage that I've found:
     APP1  = Exif (standard)
     APP1  = XMP or Adobe name-space (standard, but thanks to Adobe, it conflicts with Exif)
     APP1  = PIC (Accusoft Pegasus)
     APP2  = ICC Profile (standard)
     APP2  = Flashpix
     APP2  = MPF
     APP4  = Qualcomm Camera Debug
     APP5  = HPQ
     APP5  = ssuniqueid (Samsung)
     APP6  = MMIMETA (Motorola)
     APP7  = Gena Photo Stamper (Russian AvtoVAZ fraud)
     APP10 = AROT (Apple)
     APP10 = MOTO (Motorola)
     APP11 = JPEG2000 (JN or JPN from Microsoft Designer)
     APP11 = DP2
     APP12 = Ducky (photoshop extension; does not indicate an Adobe product!)
     APP13 = Photoshop 3.0
     APP13 = Adobe_CM
     APP14 = Adobe (does not indicate an Adobe product!)
     APP15 = Text (standard comments)
     APP15 = Q (non-standard debug code)

     See? Nobody uses APP8!
     The text string should be "SEAL\0\0".

   - Insert it as fast as possible, right after the initial FFD8.

   - If you see an MPF record (common, thanks to Apple and Samsung), then
     increment the offsets to the post-ffd9 data by the size of the SEAL data.

   - If you encounter any other blocks with a SEAL record:
     Leave it! The signature will become invalid due to the new signature.
     Optional: Prompt the user if you want to remove it.
     To remove it: don't delete! Just change the name "seal" to "seaL".
     (Why not delete? Believe me, you don't want the headache from trying to
     shrink a JPEG, especially if it's in an XMP record.)

 For decoding:
   - Skip any nested images; they are self-contained.
   - For Exif: Check for any EXIF comment, but don't scan any nested images.
   - Check any other app block.
     If any contain a regex that matches the SEAL record, then use it.
   - When you hit the ffd9, STOP! Anything else is nested.

 ************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "seal.hpp"
#include "files.hpp"
#include "seal-parse.hpp"
#include "sign-digest.hpp"
#include "sign-record.hpp"
#include "sign-local.hpp"
#include "sign-remote.hpp"
#include "sign-verify.hpp"

#pragma GCC visibility push(hidden)
/**************************************
 _JPEGblockSign(): Generate the signature block.
 If Mmap is set, then compute checksum and set @p and @s.
 Otherwise, return a stub block.
 Returns record in [@record]
 Returns block in [@JPEGblock]
 Returns offset and length to the signature in [@s]
 **************************************/
sealfield *     _JPEGblockSign   (sealfield *Args, mmapfile *Mmap, size_t Offset, uint16_t Tag)
{
  char *Opt;
  size_t i;
  sealfield *rec, *sig;

  /*****
   Load options (if present)
   Determine the type of chunk for writing.

   For signing:
   If the options includes append, then append to the file.
   If the options includes any valid PNG capitalization of
   "seAl" or "teXt", then use that chunk name for writing.
   *****/
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
        Args = SealAddText(Args,"b",",s~s+3"); // 3 for '"/>'
        }

  /*****
   create the SEAL record!
   NOTE:
   *****/
  Args = SealRecord(Args); // populate with placeholder at "@S" (capital-S)
  rec = SealSearch(Args,"@record");
  if (rec==NULL) // should never happen
    {
    printf("ERROR: Cannot generate the signature. Aborting.\n");
    exit(1);
    }

  // Compute the signature
  if (Mmap)
    {
    /*****
     The digest uses P~p and S~s (stored in @p and @s).
     However, I only have the SEAL record.
     "@S" is the signature location, relative to the start of the SEAL record.

     Make 'S~s' relative to the start of the file.
     The SEAL record is being built inside a PNG chunk.
     The PNG chunk starts at Offset (absolute file location).
     The PNG chunk has an 8 byte header (length+type).
     A text chunk has a 5 byte field (+5).
     So the start of the signature, relative to the file, is: @S + Offset + BlockHeader
     *****/
    Args = SealCopy(Args,"@sflags","@sflags"); // Flags may be updated
    Args = SealCopy(Args,"@p","@s"); // Rotates previous @s to @p
    Args = SealSetIindex(Args,"@s",0, SealGetIindex(Args,"@S",0)+Offset+2+2+5);
    Args = SealSetIindex(Args,"@s",1, SealGetIindex(Args,"@S",1)+Offset+2+2+5);

    /* Compute the digest and sign it */
    Args = SealDigest(Args, Mmap); // compute digest
    switch(SealGetCindex(Args,"@mode",0)) // sign it
      {
      case 'S': Args = SealSignURL(Args); break;
      case 's': Args = SealSignLocal(Args); break;
      default: break; // never happens
      }

    // Signature is ready-to-go in '@signatureenc'
    // Size is already pre-computed, so it will fit for overwriting.
    // Copy signature into record.
    sig = SealSearch(Args,"@signatureenc");
    memcpy(rec->Value+SealGetIindex(Args,"@S",0), sig->Value, sig->ValueLen);
    }
  /*****
   Convert the signature in '@record' to a PNG chunk.
   *****/
  Args = SealDel(Args,"@JPEGblock");

  // Insert: Block name
  Args = SealSetCindex(Args,"@JPEGblock",0,0xff);
  Args = SealSetCindex(Args,"@JPEGblock",1,Tag & 0xff);

  // Insert: Block size
  // +2 for the space needed for storing the size
  // +5 for the space name (seal)
  i = rec->ValueLen + 2 + 5;
  if (i > 0xfffe)
    {
    printf("ERROR: SEAL record is too large for JPEG. Aborting.\n");
    exit(1);
    }
  Args = SealSetCindex(Args,"@JPEGblock",2, (i>>8) & 0xff);
  Args = SealSetCindex(Args,"@JPEGblock",3, i & 0xff);
  Args = SealAddBin(Args,"@JPEGblock",5,(const byte*)"SEAL\0");

  // Insert: SEAL record
  Args = SealAddBin(Args,"@JPEGblock",rec->ValueLen, rec->Value);
  rec->Type = 'x'; // debug with hex dump

  return(Args);
} /* _JPEGblockSign() */

#pragma GCC visibility pop

/**************************************
 Seal_isJPEG(): Is this file a JPEG?
 Returns: true or false.
 **************************************/
bool    Seal_isJPEG      (mmapfile *Mmap)
{
  if (!Mmap || (Mmap->memsize < 20)) { return(false); }

  /*****
   Header begins with 0xffd8
   It is immediately followed by a tag: 0xabcd & 0xffc0 == 0xffc0.
   Warning: This can be confused with MPEG!
   *****/
  uint32_t u32;
  size_t u16,u16b;

  u32 = (Mmap->mem[0] << 24) | (Mmap->mem[1] << 16) | (Mmap->mem[2] << 8) | Mmap->mem[3];
  if ((u32 & 0xffffffc0) != 0xffd8ffc0) { return(false); } // not a jpeg

  /*****
   As a double-check, make sure the next tag looks like a JPEG block that
   points to another JPEG block.
   *****/
  u16 = (Mmap->mem[4] << 8) | Mmap->mem[5]; // should be tag length+2
  // 4 (current offset) + length (u16) should be another tag (4 bytes for tag+length)
  u16 += 4; // offset to the next tag
  if ((size_t)u16+4 >= Mmap->memsize) { return(false); } // overflow? not a jpeg

  u32  = (Mmap->mem[u16+0] << 8) | Mmap->mem[u16+1]; // check offset
  if ((u32 & 0xffc0) != 0xffc0) { return(false); } // not a jpeg
  u16b = (Mmap->mem[u16+2] << 8) | Mmap->mem[u16+3]; // check length
  if ((size_t)u16b+4 >= Mmap->memsize) { return(false); } // overflow? not a jpeg

  /*****
   Do NOT look for the final ffd9 tag!
   It's not uncommon for JPEGs to have trailer data.
   (That is, non-standard data after the end of image tag.)
   *****/

  /* Looks good! */
  return(true);   /* not a JPEG! */
} /* Seal_isJPEG() */

/**************************************
 Seal_JPEGsign(): Sign a JPEG.
 Insert a JPEG signature with Tag (APP8 or APP9).
 **************************************/
sealfield *     Seal_JPEGsign    (sealfield *Rec, mmapfile *Mmap, size_t FFDAoffset, uint16_t Tag)
{
  const char *fname;
  FILE *Fout;
  sealfield *block;
  mmapfile *Mnew;
  size_t OldBlockLen;

  fname = SealGetText(Rec,"@FilenameOut");
  if (!fname) { return(Rec); } // not signing

  // Is there an insertion point?
  if (FFDAoffset == 0)
        {
        fprintf(stderr,"ERROR: JPEG is truncated; cannot sign. Aborting.\n");
        }

  // Check if file is finalized (abort if it is)
  if (SealGetCindex(Rec,"@sflags",1)=='f')
        {
        fprintf(stderr,"ERROR: JPEG is finalized; cannot sign. Aborting.\n");
        exit(1);
        }
  Fout = SealFileOpen(fname,"w+b"); // returns handle or aborts

  // Grab the new block placeholder
  Rec = _JPEGblockSign(Rec,NULL,FFDAoffset,Tag);
  block = SealSearch(Rec,"@JPEGblock");

  // Write to file!!!
  rewind(Fout); // should not be needed

  // Store up to the 0xffda
  SealFileWrite(Fout, FFDAoffset, Mmap->mem);
  // Append signature block
  SealFileWrite(Fout, block->ValueLen, block->Value);
  // Store everything else (0xffda, stream, and any trailers)
  SealFileWrite(Fout, Mmap->memsize - FFDAoffset, Mmap->mem + FFDAoffset);
  SealFileClose(Fout);

  // Compute new digest
  Mnew = MmapFile(fname,PROT_WRITE);
  Rec = _JPEGblockSign(Rec,Mnew,FFDAoffset,Tag);
  OldBlockLen = block->ValueLen;
  block = SealSearch(Rec,"@JPEGblock");
  block->Type = 'x';
  // Block size better not change!!!
  if (OldBlockLen != block->ValueLen)
        {
        fprintf(stderr,"ERROR: record size changed while writing. Aborting.\n");
        exit(1);
        }

  // Update file with new signature
  memcpy(Mnew->mem + FFDAoffset, block->Value, block->ValueLen);
  MmapFree(Mnew);

  Rec = SealRotateRecords(Rec);
  printf(" Signature record #%ld added: %s\n",(long)SealGetIindex(Rec,"@s",2),fname);
  return(Rec);
} /* Seal_JPEGsign() */

/**************************************
 FormatJPEG(): Process a JPEG.
 Reads every seal signature.
 If signing, add the signature before the ffda stream.
 **************************************/
sealfield *	Seal_JPEG	(sealfield *Args, mmapfile *Mmap)
{
  /*****
   Walk through each JPEG block.
   If it's an APP block, check it for any signatures.
   If it's an EXIF block, give it special EXIF processing.
   If it's an MPF block, store the location because it will need
   special corrections after processing.

   Ignore all other blocks.

   =====
   Every block has:
     2-byte tag:    tag & 0xffc0 == 0xffc0
     2-byte length: This includes itself! The minimum value is "2".
     length-2 bytes data

   =====
   When iterating, use Rec instead of Args.
   This way, the scope of all values is limited to Rec.
   When this finishes, moves the values I want to keep back into Args.
   *****/
  sealfield *Rec;
  size_t RecEnd=0;
  size_t Offset;
  uint16_t BlockType, PreviousBlockType=0;
  size_t BlockSize;
  size_t FFDAoffset=0; // set when 0xffda (start of stream; SOS) insertion point is found
  size_t SearchOffset;

  Offset=2; // skip ffd8 header; it has no length.
  BlockType = 0xffd8;
  while((Offset+4 < Mmap->memsize) && (BlockType != 0xffd9))
    {
    /*****
     JPEG specs say to ignore any non-tag between blocks.
     NOTE: This almost never happens -- unless someone is intentionally
     corrupting a JPEG.
     *****/
    BlockType = (Mmap->mem[Offset+0] << 8) | Mmap->mem[Offset+1];
    if ((BlockType & 0xffc0) != 0xffc0) { Offset++; continue; }

    // Check for SOS
    if (BlockType == 0xffda) { FFDAoffset = Offset; break; } // Done!

    // Get current block size
    BlockSize = (Mmap->mem[Offset+2] << 8) | Mmap->mem[Offset+3];
    if (BlockSize < 2) // underflow
      {
      fprintf(stderr,"ERROR: JPEG is corrupted. Aborting.\n");
      return(Args);
      }
    if (Offset+BlockSize > Mmap->memsize) // overflow
      {
      fprintf(stderr,"ERROR: JPEG is corrupted. Aborting.\n");
      return(Args);
      }
    //DEBUGPRINT("Tag: %04x",(int)BlockType);

    /*****
     Scan any APP blocks for a signature
     APP blocks are ffe0 - ffef
     (ffef is a special "comment", but treat it as any other APP.)

     JPEG has this weird continuation notation.
     The max block size is 65535 bytes (0xffff).
     An APP's data may be larger than that.
     So how does JPEG handle it?
     They repeat the same APP#.
     For example if APP1 holds EXIF and EXIF spans 3 blocks,
     then it will be APP1 APP1 APP1 APP1; the decoder is expected
     to contatenate the data prior to processing.

     This leads to another problem:
     What if you have two different metadata types that use the same APP#?
     The answer?
     (A) DON'T! Choose a different APP number.
     (B) Insert some other APP number between them to break any continuation.
     (This works well-enough. Unless you're Adobe; they may ignore this rule.)

     If this makes JPEG sound like a non-standard standard, it's because
     it is. The file format has WAY too many corner case exceptions.
     *****/
    if ((BlockType & 0xfff0) == 0xffe0)
      {
      // Look for continuation blocks and skip them
      if (BlockType == PreviousBlockType) { goto NextBlock; }

      // Look for special blocks
      // MPF: Starts with "MPF\0"
      if ((BlockSize > 8) && !memcmp(Mmap->mem+Offset+4,"MPF\0",4))
	{
	// Store the first MPF
	if (!SealSearch(Args,"@jpegmpf"))
	  {
	  Args = SealSetIindex(Rec,"@jpegmpf",0,Offset+2); // start of MPF data
	  Args = SealSetIindex(Rec,"@jpegmpf",1,Offset+2+BlockSize); // end of MPF data
	  }
	// MPF doesn't support comments, so don't scan it.
	goto NextBlock;
	}

      // EXIF gets special handling
      if ((BlockSize > 8) && !memcmp(Mmap->mem+Offset+4,"Exif\0\0",6))
	{
	// TBD: Process exif which begins at Offset+10 and length is BlockSize-8
	// EXIF can be large, spanning multiple apps! SEAL must be in first block.
	goto NextBlock;
	}

      /*****
       Skip known-blocks that can contain nested media and that don't
       support their own comment structure.
       *****/
      int kl;
      static struct // known block types to skip
        {
	int LabelLen; 
	const char *Label; // some labels are null-terminated; "standard" /smh
	} KnownLabel[] =
	{
	  // Ordered by length (stop searching if it's too small)
	  { 3, "JP\0" },
	  { 4, "JPN\0" },
	  { 4, "HPQ-" },
	  { 4, "DP2\0" },
	  { 4, "PIC\0" },
	  { 5, "AROT\0" },
	  { 5, "JFIF\0" },
	  { 5, "JFXX\0" },
	  { 5, "HPSC\0" },
	  { 5, "H3X0\0" },
	  { 5, "FPXR\0" },
	  { 5, "MOTO\0" },
	  { 5, "XMTH\0" },
	  { 6, "Adobe\0" },
	  { 6, "Ducky\0" },
	  { 7, "SCRNAIL" },
	  { 7, "MMIMETA" },
	  { 8, "Ocad$Rev" },
	  { 8, "Qualcomm" },
	  { 10, "ssuniqueid" },
	  { 11, "HPQ-Capture" },
	  { 12, "ICC_PROFILE\0" },
	  { 14, "Photoshop 3.0\0" },
	  { 17, "GenaPhotoStamperd" },
	  { 0, NULL } // end marker
          // Permit "XMP\0" for XMP metadata
          // Permit "http://ns.adobe.com/\0" for XMP extension
	};
      for(kl=0; KnownLabel[kl].Label && ((size_t)KnownLabel[kl].LabelLen+2 < BlockSize); kl++)
        {
	if (!memcmp(Mmap->mem+Offset+4, KnownLabel[kl].Label, KnownLabel[kl].LabelLen))
	  {
	  //DEBUGPRINT("Skipping known: %s",KnownLabel[kl].Label);
	  goto NextBlock;
	  }
	}

      /*****
       Found a "standard" APP block (IPTC, XMP, or dozens of others).
       Scan the APP block for a signature

       WARNING: If the block contains a nested JPEG or PNG or other file
       that contains it's own SEAL signature, then this will pick it up and
       scan it, likely resulting in an invalid signature being found.

       And if the nested media is finalized, then this file cannot be signed.
       *****/
      Rec=NULL;
      SearchOffset=2; // skip size
      //DEBUGPRINT("Scanning %04x",(int)BlockType);
      while(SearchOffset < BlockSize)
	{
	Rec = SealParse(BlockSize-SearchOffset,Mmap->mem+Offset+2+SearchOffset,Offset+2+SearchOffset,Args);
	if (!Rec) { break; } // nothing found

	// Found a signature!
        // Verify the data!
        Rec = SealCopy2(Rec,"@pubkeyfile",Args,"@pubkeyfile");
        Rec = SealVerify(Rec,Mmap);

	// Iterate on remainder
	RecEnd = SealGetIindex(Rec,"@RecEnd",0);
	if (RecEnd <= 0) { RecEnd=1; } // should never happen, but if it does, stop infinite loops
	SearchOffset += RecEnd;

	// Retain state
	Args = SealCopy2(Args,"@p",Rec,"@p"); // keep previous settings
	Args = SealCopy2(Args,"@s",Rec,"@s"); // keep previous settings
	Args = SealCopy2(Args,"@dnscachelast",Rec,"@dnscachelast"); // store any cached DNS
	Args = SealCopy2(Args,"@public",Rec,"@public"); // store any cached DNS
	Args = SealCopy2(Args,"@publicbin",Rec,"@publicbin"); // store any cached DNS
	Args = SealCopy2(Args,"@sflags",Rec,"@sflags"); // retain sflags

	// Clean up
	SealFree(Rec); Rec=NULL;
	}
      }

NextBlock:
    // NEXT!
    Offset += BlockSize+2; // tag + size
    PreviousBlockType = BlockType;
    }

  /*****
   Add a signature as needed
   By default, use APP8 (ffe8).
   Unless the previous tag was APP8, then use APP9!
   *****/
  Args = Seal_JPEGsign(Args,Mmap,FFDAoffset, (PreviousBlockType == 0xffe8) ? 0xffe9 : 0xffe8);
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf("No SEAL signatures found.\n");
    }

  return(Args);
} /* FormatJPEG() */

