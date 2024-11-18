/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling Text, XML, and SVG.
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
 _isUTF8(): Is the text UTF8?
 NOTE: Only scans the first 1K.
 **************************************/
bool	_isUTF8	(mmapfile *Mmap)
{
  size_t offset=0;
  if (!Mmap || (Mmap->memsize < 8)) { return(false); }

  while((offset+5 < Mmap->memsize) && (offset < 1000))
    {
    if (isspace(Mmap->mem[offset]) || isprint(Mmap->mem[offset])) // plain text
	{
	offset++;
	}
    // U+0085 is legal and appears as a space.
    else if (Mmap->mem[offset]==0x85) // legal, appears as a space
	{
	offset++;
	}
    // 0x7f-0x84 and 0x86-0x9f: Discouraged but valid
    else if ((Mmap->mem[offset] >= 0x7f) && (Mmap->mem[offset] < 0xa0)) // U+0080 - U+009f
	{
	offset++;
	}

    // 2-byte UTF8
    else if (
	     ((0xc2 <= Mmap->mem[offset+0]) && (Mmap->mem[offset+0] <= 0xdf)) &&
	     ((0x80 <= Mmap->mem[offset+1]) && (Mmap->mem[offset+1] <= 0xbf))
	    )
	{
	offset+=2;
	}

    // 3-byte UTF8
    else if ( (// overlongs
	     (Mmap->mem[offset+0] == 0xe0) &&
	     ((0xa0 <= Mmap->mem[offset+1]) && (Mmap->mem[offset+1] <= 0xbf)) &&
	     ((0x80 <= Mmap->mem[offset+2]) && (Mmap->mem[offset+2] <= 0xbf))
	     ) ||
	     (// straight 3-byte
	     (((0xE1 <= Mmap->mem[offset+0]) && (Mmap->mem[offset+0] <= 0xEC)) ||
		    (Mmap->mem[offset+0] == 0xEE) ||
		    (Mmap->mem[offset+0] == 0xEF)) &&
	     ((0x80 <= Mmap->mem[offset+1]) && (Mmap->mem[offset+1] <= 0xBF)) &&
	     ((0x80 <= Mmap->mem[offset+2]) && (Mmap->mem[offset+2] <= 0xBF))
	     ) ||
	     (// surrogates
	     (Mmap->mem[offset+0] == 0xED) &&
	     ((0x80 <= Mmap->mem[offset+1]) && (Mmap->mem[offset+1] <= 0x9F)) &&
	     ((0x80 <= Mmap->mem[offset+2]) && (Mmap->mem[offset+2] <= 0xBF))
	     ) )
	{
	offset+=3;
	}

    // 4-byte UTF8
    else if ( (// planes 1-3
		(Mmap->mem[offset+0] == 0xF0) &&
		((0x90 <= Mmap->mem[offset+1]) && (Mmap->mem[offset+1] <= 0xBF)) &&
		((0x80 <= Mmap->mem[offset+2]) && (Mmap->mem[offset+2] <= 0xBF)) &&
		((0x80 <= Mmap->mem[offset+3]) && (Mmap->mem[offset+3] <= 0xBF))
	      ) ||
	    (// planes 4-15
		((0xF1 <= Mmap->mem[offset+0]) && (Mmap->mem[offset+0] <= 0xF3)) &&
		((0x80 <= Mmap->mem[offset+1]) && (Mmap->mem[offset+1] <= 0xBF)) &&
		((0x80 <= Mmap->mem[offset+2]) && (Mmap->mem[offset+2] <= 0xBF)) &&
		((0x80 <= Mmap->mem[offset+3]) && (Mmap->mem[offset+3] <= 0xBF))
	    ) ||
	    (// plane 16
		(Mmap->mem[offset+0] == 0xF4) &&
		((0x80 <= Mmap->mem[offset+1]) && (Mmap->mem[offset+1] <= 0x8F)) &&
		((0x80 <= Mmap->mem[offset+2]) && (Mmap->mem[offset+2] <= 0xBF)) &&
		((0x80 <= Mmap->mem[offset+3]) && (Mmap->mem[offset+3] <= 0xBF))
	    )
	)
	{
	offset+=4;
	}

    else { return(false); }
    } // while checking bytes

  return(true);
} /* _isUTF8() */

#pragma GCC visibility pop

/**************************************
 Seal_isText(): Is this file a Text?
 Returns: true or false.
 **************************************/
bool	Seal_isText	(mmapfile *Mmap)
{
  return(_isUTF8(Mmap));
} /* Seal_isText() */

/**************************************
 Seal_Textsign(): Sign a Text.
 Insert a Text signature.
 **************************************/
sealfield *	Seal_Textsign	(sealfield *Args, mmapfile *MmapIn)
{
  /*****
   WHERE to insert the signature is dependent on the type of text.

   For 1st tag:
   - If first non-whitepace character is not "<", then it's Text.
     Otherwise, it may be XML (SVG, HTML, etc.).

   - If it begins with an XML tag, then insert before the root.
     The root is the first tag that begins with "<[[:alpha:]]".
   - Non-XML (text) inserts at the end.

   For append:
   - Inserts at the end.

   XML records use "<?seal ....>".
   Text records use "<seal ...>".
   And in both cases, maintain the newline characters!
     CR or CRLF.
   *****/
  const char *fname;
  sealfield *rec; // SEAL record
  char *Opt;
  mmapfile *MmapOut;
  size_t InsertOffset,i,IsRoot;
  bool IsXML;
  byte CRLF=0; // '\n' for LF.  '\r' for CRLF, and 0 for unset.

  fname = SealGetText(Args,"@FilenameOut");
  if (!fname || !fname[0] || !MmapIn) { return(Args); } // not signing

  // Find type of file
  InsertOffset = MmapIn->memsize;

  // skip initial whitespace
  for(i=0; (i < InsertOffset) && isspace(MmapIn->mem[i]); i++) { ; }

  // With XML, first non-space character is '<'.

  // Check if it's XML, HTML, SVG, etc.
  IsRoot=0; // haven't found a root tag yet
  IsXML=false; // assume text
  if (MmapIn->mem[i]=='<') { IsXML=true; } // could be XML!

  // Scan XML and see if it really looks like XML.
  // NOTE: This is NOT a full XML parser! It assumes the XML is well-formed.
  while(IsXML && !IsRoot && (i+5 < InsertOffset))
    {
    if (isspace(MmapIn->mem[i])) { i++; continue; } // skip spaces

    // Non-roots have <?...> or <!...>
    if (!memcmp(MmapIn->mem+i,"<?",2) || !memcmp(MmapIn->mem+i,"<!",2)) { i+=2; }
    else if (MmapIn->mem[i]=='<')
	{
	// First character is alpha, :, or _
	if (isalpha(MmapIn->mem[i+1]) || strchr("_:",MmapIn->mem[i+1])) { IsRoot=i; }
	i+=1;
	}
    else { IsXML=false; }

    // Still looks like XML? Find the end of the tag!
    if (IsXML)
    	{
	// Check for tag and end tag marker.
	// First character is alpha, :, or _
	if (!isalpha(MmapIn->mem[i]) && !strchr("_:",MmapIn->mem[i])) { IsXML=false; break; }
	i++;

	// Second character: alnum, : . -
	while(IsXML && (i < MmapIn->memsize))
	  {
	  if (isspace(MmapIn->mem[i])) { break; } // divider before attributes
	  if (MmapIn->mem[i] == '>') { break; } // end tag
	  if ((i+1 < MmapIn->memsize) && !memcmp(MmapIn->mem+i,"/>",2)) { i++; break; } // end tag
	  if (!isalnum(MmapIn->mem[i]) && !strchr("_:.-",MmapIn->mem[i])) { IsXML=false; }
	  i++;
	  }

	// Find end of tag
	if (IsXML && isspace(MmapIn->mem[i]))
	  {
	  while(IsXML && (i < MmapIn->memsize))
	    {
	    if (MmapIn->mem[i] == '>') { i++; break; } // end tag
	    if (MmapIn->mem[i] == '<') { IsXML=false; } // bad start tag
	    i++;
	    }
	  }
	} // if scanning XML tag
    } // while validating XML

  // Check if insert point moved.
  // Must be XML with a root and no prior signatures.
  if (IsXML && IsRoot && (SealGetIindex(Args,"@s",2)==0))
    {
    InsertOffset=IsRoot;
    }

  // Find type of newline
  for(i=0,CRLF=0; i < MmapIn->memsize; i++)
    {
    if (!CRLF && isspace(MmapIn->mem[i])) { CRLF=MmapIn->mem[i]; }
    if (MmapIn->mem[i]=='\n')
	{
	if ((i > 0) && (MmapIn->mem[i-1]=='\r')) { CRLF='\r'; }
	else { CRLF='\n'; }
	break;
	}
    }

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
  else // if appending
	{
	InsertOffset = MmapIn->memsize; // append always goes at the end
	Args = SealAddText(Args,"b",",s~s+3"); // +3 for '"/>' or '"?>'
	//fprintf(stderr," ERROR: This format (Text) does not support appending. Skipping.\n");
	}

  // Get the record
  Args = SealRecord(Args); // get placeholder

  // Create the block
  Args = SealSetText(Args,"@BLOCK","");
  if (!IsXML)
    {
    switch(CRLF)
      {
      case '\r': Args = SealSetText(Args,"@BLOCK","\r\n"); break;
      case '\n': Args = SealSetText(Args,"@BLOCK","\n"); break;
      case 0: break; // do nothing
      // default? Whatever whitespace they used.
      default: Args = SealAddC(Args,"@BLOCK",CRLF); break;
      }
    }

  // Make '@s' relative to block
  rec = SealSearch(Args,"@BLOCK");
  SealIncIindex(Args, "@s", 0, rec->ValueLen + (IsXML ? 1 : 0)); // 4 for "!-- "
  SealIncIindex(Args, "@s", 1, rec->ValueLen + (IsXML ? 1 : 0));

  // Add record
  rec = SealSearch(Args,"@record");
  if (IsXML)
    {
    // replace "<seal ... />" with "<?seal ... ?>".
    Args = SealAddTextLen(Args,"@BLOCK",2,"<?");
    Args = SealAddBin(Args,"@BLOCK",rec->ValueLen-3,rec->Value+1); // remove "<" and "/>"
    Args = SealAddTextLen(Args,"@BLOCK",2,"?>");
    }
  else
    {
    Args = SealAddBin(Args,"@BLOCK",rec->ValueLen,rec->Value);
    }
  switch(CRLF)
    {
    case '\r': Args = SealAddText(Args,"@BLOCK","\r\n"); break;
    case '\n': Args = SealAddText(Args,"@BLOCK","\n"); break;
    default: break; // no newline
    }
  SealSetType(Args,"@BLOCK",'x');
 
  MmapOut = SealInsert(Args,MmapIn,InsertOffset);
  if (MmapOut)
    {
    // Sign it!
    SealSign(Args,MmapOut);
    MmapFree(MmapOut);
    }
  
  return(Args);
} /* Seal_Textsign() */

/**************************************
 Seal_Text(): Process a Text.
 Reads every seal signature.
 If signing, add the signature before the IEND tag.
 **************************************/
sealfield *	Seal_Text	(sealfield *Args, mmapfile *Mmap)
{
  // Make sure it's a Text.
  if (!_isUTF8(Mmap)) { return(Args); }

  // Scan text for any/all SEAL records
  Args = SealVerifyBlock(Args, 0, Mmap->memsize, Mmap);

  /*****
   Sign as needed
   *****/
  Args = Seal_Textsign(Args,Mmap); // Add a signature as needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_Text() */

