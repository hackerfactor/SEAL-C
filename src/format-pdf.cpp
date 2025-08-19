/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling PDF files.

 PDFs are absolutely horribly over-complex.
 Basic objects have a three-part layout, with each part being optional:
   <<dictionary>>
   stream
   data

 The specs say that an object cannot have both data and stream,
 but I've seen objects that contain both.

 A stream only exists if the dictionary says it exists. (Streams
 must have a "/Length" dictionary entry.)
 Streams can also be compressed and/or encoded via a variety of filters.


 Each object has an identifier with an ID and generation/revision number.
   [id] [rev] "obj"
   <<dictionary>>
   stream|data
   "endobj"
 The rev is almost always zero.
 The specs say the rev should be incremented if there is an update, but
 I've never seen this case.

 If there is a stream, then the dictionary will have a "/Length" and the
 stream will be wrapped in:
   "stream"
   [binary data..]
   "endstream"
 The binary data will end with a '\n', '\r', or '\r\n' and followed
 by the "endstream" literal.

 And that brings up whitespace...
 Literal strings must be separated by whitespace.  This is typically
 '\n', '\r', or '\r\n', but can be spaces.

 Dictionary uses a slash to denote a defined string: /Length, /Type.
 <...>, (...), and [...] denote different literal encodings.
 <<...>> denotes a sub-dictionary.
 Whitespace is used to separate values (to prevent defined strings from
 running together).  However, this doesn't stop them from being adjacent
 if there is no readability problem:
   /Length 1234 (good)
   /Length1234  (bad since they run together)
   /Type /XRef  (good)
   /Type/XRef   (also good since the slashes stop letter adjacency)
 Finally, objects can reference other objects using a postfix notation:
   id rev "R"
 The "R" means "by reference".
   /Size 12 0 R
 This says that the value for "/Size" is found in object ID 12 0.


 With PDF 1.5, there can also be compressed objects (/ObjStm).
 This requires a "/XRef" index to identify it.
 Each /ObjStm contains an index table followed by a set of objects.
 The index table has pairs of numbers: id offset
 However, the offset is not from the start of the stream; it is
 from an arbitrary offset specified in the object's dictionary.
 (Typically points to one space after the index table.)
 NOTE: The rev is not definable and is ALWAYS zero.
 If an /ObjStm is updated by another /ObjStm, then you will have
 two objects with the exact same id and rev.  This shouldn't
 be a problem since the /XRef stream will only reference one of them.
 The other (duplicate) is treated as a "hidden object" (name from
 the specs) -- it is defined but never used, and only appears after
 an edit.


 Objects are found using an index table.
 There are two types of indexes!
   xref :: a basic text table (an "xref table").
   /XRef :: a binary table stored in an object (an "XRef stream").

 An index table is prefaced with the first index number and number
 of records.  This is followed by the records in a FORTRAN format:
   5 7
   0000267453 00000 n
   0000000000 65535 f
   ...
 This says that there are 7 entries and the first ID is "5".
 Type "n" means it is in-use.  The first field contains the absolute
 byte offset to the object and second is the object's revision.  So 
 object ID 5 0 is at offset 267453.
 Type "f" means the object is free.  The offset is zero (since it
 does not exist) and the revision points to the next free object,
 or 65535 if it is the last free object.
 Special case: an object type "n" with offset 0 is "deleted".
 If the object does exist in the PDF file, it is unused (hidden/unindexed).

 With an xref stream, it is a binary structure with three columns: type aa bb
   type 0: free; aa and bb are unused.
   type 1: uncompressed; aa is the absolute byte position to the object and
     bb is the object revision number.
   type 2: compressed; aa is the object ID of the /ObjStm containing it, and
     bb is the relative position in the ObjStm binary stream.
     E.g., 2 1234 3
     "2" means compressed.  Found in "ID 1234 0", and it will be the 4th (#3)
     object defined in the stream.
     Notice how it doesn't have the option to specify the revision for the
     containing object.  Every object of type /ObjStm MUST have revision zero.
     (Basically, whoever hacked together this table broke the PDF revision
     concept.)


 So how do you find an index?
 There are three ways...

 Method #1 (old-PDF, the most common method)
   xref
   [xref table]
   trailer
   <<dictionary>>
   startxref
   [offset]
   %%EOF
 The PDF will end with a startxref block that points to the absolute
 byte position of an xref table.  The trailer looks like an object
 with a dictionary (but no object ID) and contains a dictionary that
 defines where the PDF root (/Catalog) is located, meta data, and
 optional encryption parameters.

 Method #2 (supported by PDF 1.5 and later)
 There is no trailer; just a startxref.
 The offset after the startxref is the absolute byte position of
 an object that defines the xref stream: /Type /XRef
 Each "/Type /XRef" object may link to another /Type /XRef object
 using the "/Prev offset" directionary entry to specify the
 absolute offset to the previous xref stream.

 Method #3: hybrid
 So an old PDF with an xref table is updated by an editor that
 wants to use an XRef stream... and rewriting the entire file
 would be too easy.
 In the first trailer (from the pre-edit document), they add in
 a "/XRefStm offset" dictionary entry.  The offset points to
 an xref stream object (/Type /XRef).  This is almost always a
 forward reference.

 A hybrid can also be used to permit both old and new PDF readers
 to access the file.  (Even though newer ones must support the
 older index method...)

 A hybrid PDF file can easily contain hidden objects (unindexed)
 if the updated xref stream defines the same object found in the
 older xref table.

 As far as I can tell, there is no way for an editor to add an
 xref table to an xref stream file.  Hybrids support backwards
 compatibility, not forward compatibility.


 The contents of the startxref varies based on the preceding trailer.
 If there is no trailer, then startxref points to an XRef stream object.
 If there is a trailer, then startxref points to an xref table.

 =================
 PDF Encryption

 The trailer (for xref table) and /Type /XRef object (for XRef streams)
 may have a /Encrypt dictionary entry.  This means that every object
 associated with the xref index (table or stream) is encrypted.

 The /Encrypt entry will point to an object that contains the
 crypto parameters.

 Each encrypted object will have:
   - Stream encrypted.
   - Any dictionary value that uses "(string)" (in parenthesis)
     is encrypted.
   + Other dictionary values are unencrypted.
   + Data (not stream) after the dictionary is not encrypted.
 For compressed objects, only containing stream (from the /ObjStm object)
 is encrypted. (No need to encrypt items in an already-encrypted stream.)

 =================
 What about SEAL?
   - The format of the SEAL record "<...>" conflicts with the dictionary format.
     It cannot go in a dictionary.

   - I could define my own object type, like /Type SEAL, and then put the
     record in the object's stream.
     But for inserting/appending, this could mean rewriting existing index
     tables, which would invalidate previous signatures.

   - But what about comments?
     With every other file format, a SEAL record can be inserted in a comment.
     With PDF, any line with a "%" outside of a string or stream is a comment!
     (PDF32000.book, section 7.2.3: Comments.)
     (Yes, the initial "%PDF", BOM, and ending "%%EOF" are just comments!)
     Also, by convention, a "%%" denotes something related to the structure or
     content, and not a generic comment.  As shown in PDF32000.book:
       %%EOF   :: is the end of file.
       %%text  :: is used to comment the structure. 
       %%ImageFilename  :: Table 370, an OPI comment for an external file.
       %%MainImage  :: Table 370, an OPI comment for an external file.
       etc.

     The very end of the file has a 'trailer' with an absolute offset into
     the file.  This is followed by a "%%EOF".
     If I insert a "%%<seal ...>" right before the "%%EOF", then:
     1. It's a legitimate comment.
     2. Insertion doesn't require rewriting any of the previous tables or pointers.
     3. Any alteration to the file will be caught by the signature.
     4. PDFs permit appending. They can insert new tables and new trailer info
	before the "%%EOF" and after the existing trailer.
	This means data can be appended and an appended SEAL can then be provided.

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
 _PDFwalk(): Traverse a PDF and identify any non-object comments.
 Scan comments for SEAL records.
 Marks location of final "%%EOF"
 **************************************/
sealfield *	_PDFwalk	(sealfield *Args, mmapfile *Mmap)
{
  size_t Pos; // position of last obj and endobj
  int Objcount=0; // +1 for obj, -1 for endobj

  Pos=0;
  while(Pos < Mmap->memsize)
    {
    /*****
     Start of object [[:space:]][[:digit:]]+[[:space:]][:digit:]]+[[:space:]]obj[[:space:]]
     Will be paired with endobj
     Start may be followed by a dictionary: <<[^>]+>>
       Dictionary may contain a /Length[[:space:]]bytes; number of bytes after the ">>".
     Start may be followed by: stream
       Terminated by endstream

     I'm interested in:
       - The gap before the first obj
       - The gap between endobj and next obj
       - The gap after the last endobj

     There are LOTS of PDF libraries out there.
     However, they are focused on objects and skip comments.
     I'm focused on comments, not objects.

     One other note:
     Minimum SEAL record: <seal seal=1 d=1 s=1/>
     That's 22 characters.
     *****/
    if ((Pos+5 < Mmap->memsize) && isspace(Mmap->mem[Pos]) && !memcmp(Mmap->mem+Pos+1,"obj",3) && isspace(Mmap->mem[Pos+4]))
	{
	Objcount++;
	Pos+=5;
	}
    else if ((Pos+6 < Mmap->memsize) && !memcmp(Mmap->mem+Pos,"endobj",6) && isspace(Mmap->mem[Pos+6]))
	{
	Pos+=7;
	if (Objcount > 0) { Objcount--; }
	}
    else if (!Objcount && // if outside of an object
	     (Pos+5 <= Mmap->memsize) && // and enough room for a SEAL record
	     !memcmp(Mmap->mem+Pos,"%%EOF",5) && // and looks like EOF
	     ((Pos+5 >= Mmap->memsize) || isspace(Mmap->mem[Pos+5])) )
	{
	Args = SealSetIindex(Args,"@PDF_EOF",0,Pos);
	Pos+=6;
	}

    else if (!Objcount && // if outside of an object
	     (Pos+23 < Mmap->memsize) && // and enough room for a SEAL record
	     !memcmp(Mmap->mem+Pos,"%<seal ",7)) // and looks like a SEAL record
	{
	size_t pend; // end of the comment line
	for(pend=Pos+1; (pend < Mmap->memsize) && !strchr("\r\n",Mmap->mem[pend]); pend++) { ; }
	Args = SealVerifyBlock(Args, Pos, pend, Mmap, NULL);
	Pos=pend;
	}
    else { Pos++; }
    }

  return(Args);
} /* _PDFwalk() */

#pragma GCC visibility pop

/**************************************
 Seal_isPDF(): Is this file a PDF?
 Returns: true or false.
 **************************************/
bool	Seal_isPDF	(mmapfile *Mmap)
{
  size_t eof;
  if (!Mmap || (Mmap->memsize < 20)) { return(false); }

  if (memcmp(Mmap->mem,"%PDF",4)) { return(false); }  /* not a PDF! */

  // End may contain a newline.
  for(eof=Mmap->memsize-1; (eof > 20) && isspace(Mmap->mem[eof]); eof--) { ; }
  // PDF ends with newline+%%EOF
  if (!strchr("\r\n",Mmap->mem[eof-5]) || memcmp(Mmap->mem+eof-4,"%%EOF",5))
	{ return(false); }  /* not a PDF! */

  return(true);
} /* Seal_isPDF() */

/**************************************
 Seal_PDFsign(): Sign a PDF.
 Insert a PDF signature.
 **************************************/
sealfield *	Seal_PDFsign	(sealfield *Rec, mmapfile *MmapIn, size_t EOF_offset)
{
  const char *fname;
  mmapfile *MmapOut;
  sealfield *rec;
  char *Opt;

  fname = SealGetText(Rec,"@FilenameOut");
  if (!fname || !fname[0]) { return(Rec); } // not signing

  // Is there an insertion point?
  if (EOF_offset == 0)
	{
	fprintf(stderr," ERROR: PDF is truncated; cannot sign. Aborting.\n");
	}

  // Check if file is finalized (abort if it is)
  if (strchr(SealGetText(Rec,"@sflags"),'F')) // if exists, then append
	{
	fprintf(stderr," ERROR: PDF is finalized; cannot sign. Aborting.\n");
	exit(0x80);
	}

  /*****
   Determine the byte range for the digest.
   The first record should start from the start of the file.
   The last record goes to the end of the file. Unless...
   Unless it is appending.
   *****/
  Opt = SealGetText(Rec,"options"); // grab options list
  Rec = SealDel(Rec,"b");
  if (SealGetCindex(Rec,"@sflags",0)=='F') // if exists, then append
	{
	// if appending, overlap signatures to prevent insertion attacks.
	Rec = SealSetText(Rec,"b","P");
	}
  else
	{
	// if starting from the beginning of the file
	Rec = SealSetText(Rec,"b","F");
	}
  // Range covers signature and end of record.
  Rec = SealAddText(Rec,"b","~S");

  // Check for appending
  if (!Opt || !strstr(Opt,"append")) // if not append
	{
	// Skip the PNG checksum and finalize to the end of file ("f")
	Rec = SealAddText(Rec,"b",",s~f");
	}
  else
	{
	Rec = SealAddText(Rec,"b",",s~s+5"); // +3 for '"/>'
	}

  // Get the record
  Rec = SealRecord(Rec); // make the @record placeholder

  // Create the block
  Rec = SealSetTextLen(Rec,"@BLOCK",2,"%%"); // comment
  // Make "@s" relative to the start of the block
  SealIncIindex(Rec, "@s", 0, 2);
  SealIncIindex(Rec, "@s", 1, 2);
  rec = SealSearch(Rec,"@record");
  Rec = SealAddBin(Rec,"@BLOCK",rec->ValueLen, rec->Value);

  /*****
   PDF is inconsistent with newlines.
   I've seen \n, \r, \r\n, and even files with mixed newlines!
   *****/
  Rec = SealAddText(Rec,"@BLOCK","\r\n"); // add final newline

  // Write the output; append new record to the end of the file
  MmapOut = SealInsert(Rec,MmapIn,EOF_offset);
  if (MmapOut)
    {
    // Sign it!
    SealSign(Rec,MmapOut,NULL);
    MmapFree(MmapOut);
    }

  return(Rec);
} /* Seal_PDFsign() */

/**************************************
 Seal_PDF(): Process a PDF.
 Reads every seal signature.
 If signing, add the signature before the final %%EOF tag.
 **************************************/
sealfield *	Seal_PDF	(sealfield *Args, mmapfile *Mmap)
{
  size_t EOF_offset=0;

  // Make sure it's a PDF.
  if (!Seal_isPDF(Mmap)) { return(Args); }

  // Scan PDF for known SEAL records
  Args = _PDFwalk(Args,Mmap);
  EOF_offset = SealGetIindex(Args,"@PDF_EOF",0);
  Args = SealDel(Args,"@PDF_EOF");
  if (!EOF_offset)
	{
	printf(" ERROR: Truncated or invalid PDF. Aborting.\n");
	return(Args);
	}

  /*****
   Sign as needed
   *****/
  Args = Seal_PDFsign(Args,Mmap,EOF_offset); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_PDF() */

