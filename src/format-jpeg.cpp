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
     fffe :: text comment
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

 ====
 Special case: MPF
 The "Multi-Picture Format" is an APP block that references images stored
 after the end of the JPEG. (Why? Because why should they follow the standard?)
 This is commonly used by Apple and Samsung to store depth maps, and by some
 cameras for storing large preview images.

 The APP block points to an offset after the image.

 Problem #1:
 If SEAL inserts data, then the offset will be wrong.
 Detect this case and fix it.

 Problem #2:
 If SEAL appeands a 2nd signature, then either the offset will be wrong,
 *or* we correct the offset but then the previous signature will be wrong.
 Solution: For the first signature, warn if it's not finalized.
 Solution: Subsequent signtures, warn that the MPF pointers will be wrong.
   - Don't try to correct the previously fixed MPF offsets!
   - Don't exclude the MPF pointers from the signature since that can
     permit unauthorized alterations to the file.
 
 ************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <endian.h> // for MPF endian

#include "seal.hpp"
#include "files.hpp"
#include "formats.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"

#pragma GCC visibility push(hidden)
/**************************************
 _JPEGblock(): Generate the signature block.
 Return a stub block.
 Returns record in [@record]
 Returns block in [@BLOCK]
 Returns offset and length to the signature in [@s] relative to @BLOCK
 **************************************/
sealfield *     _JPEGblock   (sealfield *Args, uint16_t Tag)
{
  char *Opt;
  size_t i;
  sealfield *rec;

  /*****
   Load options (if present)
   Determine the type of chunk for writing.

   For signing:
   If the options includes append, then append to the file.
   *****/
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
	Args = SealAddText(Args,"b",",s~s+3"); // 3 for '"/>'
	}

  /*****
   create the SEAL record!
   NOTE:
   *****/
  Args = SealRecord(Args);
  rec = SealSearch(Args,"@record");
  if (rec==NULL) // should never happen
    {
    printf(" ERROR: Cannot generate the signature. Aborting.\n");
    exit(0x80);
    }

  /*****
   Convert the signature in '@record' to a JPEG chunk.
   *****/
  Args = SealDel(Args,"@BLOCK");

  // Insert: Block name
  Args = SealSetBin(Args,"@BLOCK",1,(byte*)"\xff");
  Args = SealSetCindex(Args,"@BLOCK",1,Tag & 0xff);

  // Insert: Block size
  // +2 for the space needed for storing the size
  // +5 for the space name (seal)
  i = rec->ValueLen + 2 + 5;
  if (i > 0xfffe)
    {
    printf(" ERROR: SEAL record is too large for JPEG. Aborting.\n");
    exit(0x80);
    }
  Args = SealSetCindex(Args,"@BLOCK",2, (i>>8) & 0xff);
  Args = SealSetCindex(Args,"@BLOCK",3, i & 0xff);
  Args = SealAddBin(Args,"@BLOCK",5,(const byte*)"SEAL\0");
  SealSetType(Args,"@BLOCK",'x');

  // Increment 's' relative to block
  Args = SealIncIindex(Args, "@s", 0, SealGetSize(Args,"@BLOCK"));
  Args = SealIncIindex(Args, "@s", 1, SealGetSize(Args,"@BLOCK"));

  // Insert: SEAL record
  Args = SealAddBin(Args,"@BLOCK",rec->ValueLen, rec->Value);
  SealSetType(Args,"@BLOCK",'x'); // debug with hex dump

  return(Args);
} /* _JPEGblock() */

/**************************************
 _SealFileWriteMPF(): Update the MPF record's offsets.
 **************************************/
void	_SealFileWriteMPF	(FILE *Fout, size_t IncValue, size_t FFDAoffset, size_t *MPFoffset, mmapfile *Mmap)
{
  /*****
   Multi-Picture Format
   Ref: https://web.archive.org/web/20130921053834/http://www.cipa.jp/english/hyoujunka/kikaku/pdf/DC-007_E.pdf
   (If you thought JPEG was overly complicated, wait until you see MPF!)

   MPF can use big or little endian for values.
   MPF uses a chain of image file directory (IFD) elements.
   Each IFD contains a list of elements.
   Some elements define the purpose, others provide pointers to data.

   4 bytes: "II\0\0" or "MM\0\0" for little or big endian.
     (II for intel/little, MM for motorola/big)
   4 bytes: Offset to first image file directory (IFD) (relative to endian definition)

   Then comes a list of 12-byte offsets for the image file directories (IFD):
     2 byte count
     2 byte type
     4 byte value
     4 byte offset to next IFD (relative to endian definition)
   If type is 0xb001, then it's the number of entries
   If type is 0xb002, then it's the offset to the entries
     Now process the entries!
     Each entry is 16 bytes.
       4 byte: attributes (type of image)
       4 byte: size
       4 byte: offset relative to the endian definition
         This needs to be incremented by IncValue.
       2 byte: dependency
       2 byte: dependency
   *****/
  int Endian=0;
  sealfield *MPF;
  size_t v, ifdoffset, type;
  size_t count, co, c;
  size_t entries, entriesoffset, eo, e, esize, eoffset;
  bool IsError=false;

  // Allocate memory
  MPF = SealSetBin(NULL, "MPF", MPFoffset[1]-MPFoffset[0], Mmap->mem + MPFoffset[0]);
  MPF->Type='x'; // for debugging

  // Skip APP header
  ifdoffset = 6; // uint16(APPlen) MPF \0

  // Find endian
  if (ifdoffset+4 > MPF->ValueLen) { IsError=true; goto MPFdone; }
  if (!memcmp(MPF->Value+ifdoffset,"II*\0",4)) { Endian = 1234; }
  else if (!memcmp(MPF->Value+ifdoffset,"MM\0*",4)) { Endian = 4321; }
  else { IsError=true; goto MPFdone; }

  // Process each IFD (stop at zero or if it tries to go backwards; no loops!
  ifdoffset+=4;
  while((ifdoffset > 0) && (ifdoffset+6+4 < MPF->ValueLen))
    {
    // Load value by endian
    if (Endian == 1234) { v = readle32(MPF->Value+ifdoffset); }
    else { v = readbe32(MPF->Value+ifdoffset); }
    v += 6; // relative to endian definition

    // Now process the records
    entriesoffset = entries = 0;
    if (v == 0) { break; } // done
    if (ifdoffset+2 > MPF->ValueLen) { IsError=true; goto MPFdone; } // overflow
    if (v <= ifdoffset) { IsError=true; goto MPFdone; } // looping
    ifdoffset = v;

    if (Endian == 1234) { count = readle16(MPF->Value+ifdoffset); }
    else { count = readbe16(MPF->Value+ifdoffset); }
    ifdoffset += 2;

    for(c=0; c < count; c++)
      {
      co = ifdoffset; // count offset
      ifdoffset += 12;

      if (co + 12 > MPF->ValueLen) { IsError=true; goto MPFdone; } // overflow
      if (Endian == 1234) { type = readle16(MPF->Value+co); }
      else { type = readbe16(MPF->Value+co); }

      co += 8;
      if (type == 0xb001) // number of images
	{
	if (Endian == 1234) { entries = readle32(MPF->Value+co); }
	else { entries = readbe32(MPF->Value+co); }
	}
      if (type == 0xb002) // if it's the offset to an image
	{
	if (Endian == 1234) { entriesoffset = readle32(MPF->Value+co); }
	else { entriesoffset = readbe32(MPF->Value+co); }
	// Ugh. The offset is relative 
	entriesoffset += 6; // relative to endian definition
	}
      } // foreach entry

    // Now process each entry for the IFD
    if (entriesoffset <= 0) { entries=0; } // not set; skip any entries
    for(e=0; e < entries; e++)
	{
        /*****
         Each entry has 16 bytes, but I only care about
         the offset bytes 8-11.
         These often point to:
           0 = base image. Yes, MPF can point to the image that contains the MPF.
	   Thumbnail in EXIF (if the EXIF comes after the MPF)
	   Some place after the end of image (0xffd9).
         I only need to fix points for anything after the 0xffda.
         *****/
        // Any overflow? Just process the next IFD.
        eo = entriesoffset + e*16;
        if (eo + 12 > MPF->ValueLen) { break; }

	// 4-bytes: skip attribute/type

	// 4-bytes: Load size
        if (Endian == 1234) { esize = readle32(MPF->Value+eo+4); }
        else { esize = readbe32(MPF->Value+eo+4); }

	// 4-bytes: Load offset
        if (Endian == 1234) { eoffset = readle32(MPF->Value+eo+8); }
        else { eoffset = readbe32(MPF->Value+eo+8); }

	// 4-bytes: Skip dependents flags

	// Now: What needs to shift???
	if ((eoffset <= FFDAoffset) && (eoffset+esize < FFDAoffset)) { ; } // no change

	else if ((eoffset <= FFDAoffset) && (eoffset+esize >= FFDAoffset)) // size grows
	  {
	  // size is going to increase 
	  esize += IncValue;
	  if (Endian == 1234) { esize = htole32(esize); }
	  else { esize = htobe32(esize); }
	  writele32(MPF->Value+eo+4,esize);
	  }

	else if (eoffset > FFDAoffset) // offset shifts
          {
	  eoffset += IncValue;
	  if (Endian == 1234) { eoffset = htole32(eoffset); }
	  else { eoffset = htobe32(eoffset); }
	  writele32(MPF->Value+eo+8,eoffset);
	  }
        } // foreach entry

    // Load pointer to next IFD
    if (Endian == 1234) { v = readle32(MPF->Value+ifdoffset); }
    else { v = readbe32(MPF->Value+ifdoffset); }
    if (v < ifdoffset) { break; } // no loops
    if (v == 0) { break; } // no next IFD
    ifdoffset = v+6;
    } // foreach item in the IFD

  
MPFdone:
  if (IsError)
    {
    printf(" ERROR: Invalid MPF metadata block; not fixing.\n");
    SealFileWrite(Fout, MPFoffset[1]-MPFoffset[0], Mmap->mem + MPFoffset[0]);
    }
  else
    {
    SealFileWrite(Fout, MPF->ValueLen, MPF->Value);
    }
  SealFree(MPF);
  return;
} /* _SealFileWriteMPF() */
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

  u32 = readbe32(Mmap->mem);
  if ((u32 & 0xffffffc0) != 0xffd8ffc0) { return(false); } // not a jpeg

  /*****
   As a double-check, make sure the next tag looks like a JPEG block that
   points to another JPEG block.
   *****/
  u16 = readbe16(Mmap->mem+4); // should be tag length+2
  // 4 (current offset) + length (u16) should be another tag (4 bytes for tag+length)
  u16 += 4; // offset to the next tag
  if ((size_t)u16+4 >= Mmap->memsize) { return(false); } // overflow? not a jpeg

  u32  = readbe16(Mmap->mem+u16); // check offset
  if ((u32 & 0xffc0) != 0xffc0) { return(false); } // not a jpeg
  u16b = readbe16(Mmap->mem+u16+2); // check length
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
sealfield *     Seal_JPEGsign    (sealfield *Rec, mmapfile *MmapIn, size_t FFDAoffset, uint16_t Tag)
{
  const char *fname;
  FILE *Fout;
  sealfield *block;
  size_t MPFoffset[2]={0,0};

  fname = SealGetText(Rec,"@FilenameOut");
  if (!fname) { return(Rec); } // not signing

  // Is there an insertion point?
  if (FFDAoffset == 0)
	{
	fprintf(stderr," ERROR: JPEG is truncated; cannot sign. Aborting.\n");
	}

  // Check if file is finalized (abort if it is)
  if (SealGetCindex(Rec,"@sflags",1)=='f')
	{
	fprintf(stderr," ERROR: JPEG is finalized; cannot sign. Aborting.\n");
	exit(0x80);
	}

  // Check for MPF
  MPFoffset[0] = SealGetIindex(Rec,"@jpegmpf",0);
  MPFoffset[1] = SealGetIindex(Rec,"@jpegmpf",1);
  if ((MPFoffset[0] > 0) && (SealGetIindex(Rec,"@s",2) > 0))
	{
	fprintf(stderr,"WARNING: JPEG's MPF metadata cannot be updated for multiple signatures.\n");
	MPFoffset[0]=0;
	}

  // Open file for writing!
  Fout = SealFileOpen(fname,"w+b"); // returns handle or aborts
  if (!Fout)
    {
    fprintf(stderr," ERROR: Cannot create file (%s). Aborting.\n",fname);
    exit(0x80);
    }

  // Grab the new block placeholder
  Rec = _JPEGblock(Rec,Tag); // populates "@BLOCK"
  block = SealSearch(Rec,"@BLOCK");

  // Write to file!!!
  // NOTE: Not using SealInsert() because of special case MPF
  rewind(Fout); // should not be needed

  // Store up to the 0xffda
  if (MPFoffset[0] == 0)
    {
    SealFileWrite(Fout, FFDAoffset, MmapIn->mem);
    }
  else
    {
    // Write up to MPF
    SealFileWrite(Fout, MPFoffset[0], MmapIn->mem);
    // Write updated MPF
    _SealFileWriteMPF(Fout, block->ValueLen, FFDAoffset, MPFoffset, MmapIn);
    // Write from end-of-MPF to 0xffda
    SealFileWrite(Fout, FFDAoffset - MPFoffset[1], MmapIn->mem + MPFoffset[1]);
    }

  // Make 's' offset relative to the file
  {
  size_t *s;
  s = SealGetIarray(Rec,"@s");
  s[0] += ftell(Fout);
  s[1] += ftell(Fout);
  }

  // Append signature block
  SealFileWrite(Fout, block->ValueLen, block->Value);

  // Store everything else (0xffda, stream, and any trailers)
  SealFileWrite(Fout, MmapIn->memsize - FFDAoffset, MmapIn->mem + FFDAoffset);
  SealFileClose(Fout);

  // Insert new signature
  mmapfile *MmapOut;
  MmapOut = MmapFile(fname,PROT_WRITE);
  SealSign(Rec,MmapOut);
  MmapFree(MmapOut);

  return(Rec);
} /* Seal_JPEGsign() */

/**************************************
 Seal_JPEG(): Process a JPEG.
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
  size_t Offset;
  uint16_t BlockType, PreviousBlockType=0;
  size_t BlockSize;
  size_t FFDAoffset=0; // set when 0xffda (start of stream; SOS) insertion point is found

  Offset=2; // skip ffd8 header; it has no length.
  BlockType = 0xffd8;
  Args = SealDel(Args,"@jpegmpf"); // make sure it's clean

  while((Offset+4 < Mmap->memsize) && (BlockType != 0xffd9))
    {
    /*****
     JPEG specs say to ignore any non-tag between blocks.
     NOTE: This almost never happens -- unless someone is intentionally
     corrupting a JPEG.
     *****/
    BlockType = readbe16(Mmap->mem+Offset);
    if ((BlockType & 0xffc0) != 0xffc0) { Offset++; continue; }

    // Check for SOS
    if (BlockType == 0xffda) { FFDAoffset = Offset; break; } // Done!

    // Get current block size
    BlockSize = readbe16(Mmap->mem+Offset+2);
    if (BlockSize < 2) // underflow
      {
      fprintf(stderr," ERROR: JPEG is corrupted. Aborting.\n");
      return(Args);
      }
    if (Offset+BlockSize > Mmap->memsize) // overflow
      {
      fprintf(stderr," ERROR: JPEG is corrupted. Aborting.\n");
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

      /***** Look for special blocks *****/
      // MPF: Starts with "MPF\0"
      if ((BlockSize > 8) && !memcmp(Mmap->mem+Offset+4,"MPF\0",4))
	{
	// Store the first MPF
	if (!SealSearch(Args,"@jpegmpf"))
	  {
	  Args = SealSetIindex(Args,"@jpegmpf",0,Offset+2); // start of MPF data
	  Args = SealSetIindex(Args,"@jpegmpf",1,Offset+2+BlockSize); // end of MPF data
	  }
	// MPF doesn't support comments, so don't scan it.
	goto NextBlock;
	}

      // EXIF gets special handling
      if ((BlockSize > 8) && !memcmp(Mmap->mem+Offset+4,"Exif\0\0",6))
	{
	// Process exif which begins at Offset+10 and length is BlockSize-8
	// EXIF can be large, spanning multiple apps! SEAL must be in first block.
	// Process possible EXIF for SEAL record.
	mmapfile MmapExif;
	MmapExif.mem = Mmap->mem+Offset+10;
	MmapExif.memsize = BlockSize-8;
	Args = Seal_Exif(Args,&MmapExif);
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
	  { 6, "AJPEG\0" },
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
      Args = SealVerifyBlock(Args, Offset+2, Offset+2+BlockSize, Mmap);
      } // if APP block
    else if (BlockType == 0xfffe)
      {
      Args = SealVerifyBlock(Args, Offset+2, Offset+2+BlockSize, Mmap);
      } // if comment block

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
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_JPEG() */

