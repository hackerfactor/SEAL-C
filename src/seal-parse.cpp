/************************************************
 SEAL: implemented in C
 See LICENSE

 Parsing a SEAL record.
 These are in text the form:
   <seal ... />
 or in XMP form:
   <*:seal>&lt;seal ... /&gt;</\*:seal>
   <*:seal seal='&lt;seal .../&gt;' />
   Where '*' is a namespace
   Where "..." are attributes in the format: field=value.
 or generic XML/SVG/HTML:
   <?seal ... ?>

 The first attribute MUST be "seal=" and a version.
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

// For Base64
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "seal.hpp"
#include "seal-parse.hpp"

struct {
  int len;
  const char *code;
  const char c;
  } entities[] =
  {
    { 5, "&lt;", '<' },
    { 5, "&gt;", '>' },
    { 6, "&quot;", '"' },
    { 6, "&apos;", 0x27 },
    { 5, "&amp;", '&' },
    { 0, NULL, 0 }
  };

/**************************************
 SealStrDecode(): Given a string, remove \quote
 **************************************/
void	SealStrDecode	(sealfield *Data)
{
  // Do the decoding inline
  size_t i,j;
  if (!Data || !Data->ValueLen) { return; }
  for(i=j=0; i < Data->ValueLen; i++,j++)
    {
    if (Data->Value[i]=='\\') { i++; }
    if (i!=j) { Data->Value[j]=Data->Value[i]; }
    }
  if (j < i) { memset(Data->Value+j,0,i-j); }
  Data->ValueLen = j;
} /* SealStrDecode() */

/**************************************
 SealStrEncode(): Given a string, add \quote
 **************************************/
void	SealStrEncode	(sealfield *Data)
{
  size_t i,j;

  if (!Data || !Data->ValueLen) { return; }

  // Count amount of new space required
  for(i=j=0; i < Data->ValueLen; i++,j++)
    {
    if (strchr("'\"\\",Data->Value[i])) { j++; }
    }

  // i=string length, j=new string length
  if (j > i)
    {
    Data->ValueLen=j;
    Data->Value = (byte*)realloc(Data->Value,Data->ValueLen+4);
    memset(Data->Value+i,0,j-i+4); // clear new memory
    // Now copy over all new characters
    // Start at the last character
    // NOTE: Can't check if (i >= 0) since size_t is unsigned; always true.
    while((i > 0) && (j > i))
      {
      Data->Value[j-1] = Data->Value[i-1];
      if (strchr("'\"\\",Data->Value[i-1]))
        {
	j--;
	Data->Value[j-1]='\\';
	}
       j--; i--;
      }
    }
} /* SealStrEncode() */

/**************************************
 SealXmlDecode(): Given a string, convert &entity; to utf8
 **************************************/
void	SealXmlDecode	(sealfield *Data)
{
  // Do the decoding inline
  int e,n;
  size_t i,j;
  if (!Data || !Data->ValueLen) { return; }

  for(i=j=0; i < Data->ValueLen; i++,j++)
    {
    if (i!=j) { Data->Value[j]=Data->Value[i]; }
    // Check for hex encoding
    if ((i+5 <= Data->ValueLen) && !memcmp(Data->Value+i,"&#x",3))
	{
	// Replace hex code with character
	i+=3;
	n=0;
	for( ; (i < Data->ValueLen) && isxdigit(Data->Value[i]); i++)
	  {
	  n *= 16;
	  if (isdigit(Data->Value[i])) { n += Data->Value[i]-'0'; }
	  else if (isupper(Data->Value[i])) { n += Data->Value[i]-'A'+10; }
	  else { n += Data->Value[i]-'a'+10; }
	  }
	i++; // skip semicolon
	if (n > 0xffffff)
	  {
	  Data->Value[j]=(n >> 24)&0xff; j++;
	  Data->Value[j]=(n >> 16)&0xff; j++;
	  Data->Value[j]=(n >> 8)&0xff; j++;
	  Data->Value[j]=n & 0xff; j++;
	  }
	else if (n > 0xffff)
	  {
	  Data->Value[j]=(n >> 16)&0xff; j++;
	  Data->Value[j]=(n >> 8)&0xff; j++;
	  Data->Value[j]=n & 0xff; j++;
	  }
	else if (n > 0xff)
	  {
	  Data->Value[j]=(n >> 8)&0xff; j++;
	  Data->Value[j]=n & 0xff; j++;
	  }
	else if (n > 0)
	  {
	  Data->Value[j]=n & 0xff; j++;
	  }
	}
    // check for decimal encoding
    else if ((i+4 <= Data->ValueLen) && !memcmp(Data->Value+i,"&#",2))
	{
	// Replace decimal code with character
	i+=2;
	n=0;
	for( ; (i < Data->ValueLen) && isdigit(Data->Value[i]); i++)
	  {
	  n *= 10;
	  n += Data->Value[i]-'0';
	  }
	i++; // skip semicolon
	if (n > 0xffffff)
	  {
	  Data->Value[j]=(n >> 24)&0xff; j++;
	  Data->Value[j]=(n >> 16)&0xff; j++;
	  Data->Value[j]=(n >> 8)&0xff; j++;
	  Data->Value[j]=n & 0xff; j++;
	  }
	else if (n > 0xffff)
	  {
	  Data->Value[j]=(n >> 16)&0xff; j++;
	  Data->Value[j]=(n >> 8)&0xff; j++;
	  Data->Value[j]=n & 0xff; j++;
	  }
	else if (n > 0xff)
	  {
	  Data->Value[j]=(n >> 8)&0xff; j++;
	  Data->Value[j]=n & 0xff; j++;
	  }
	else if (n > 0)
	  {
	  Data->Value[j]=n & 0xff; j++;
	  }
	}
    // check for entities encoding
    else
      {
      for(e=0; entities[e].len > 0; e++)
        {
        if ((i+entities[e].len <= Data->ValueLen) &&
	    !memcmp(Data->Value+i,entities[e].code,entities[e].len))
	  {
	  // Replace named entity with character
	  Data->Value[j] = entities[e].c;
	  i += entities[e].len-1;
	  break;
	  }
        }
      }
    }
  if (j < i) { memset(Data->Value+j,0,i-j); }
  Data->ValueLen = j;
} /* SealXmlDecode() */

/**************************************
 SealXmlEncode(): Given a string, encode any XML entities
 **************************************/
void	SealXmlEncode	(sealfield *Data)
{
  int e;
  size_t i,j;

  if (!Data || !Data->ValueLen) { return; }

  // Count amount of new space required
  for(i=j=0; i < Data->ValueLen; i++,j++)
    {
    j++;
    if (!isprint(Data->Value[i])) { j+=5; continue; }
    for(e=0; entities[e].len; e++)
      {
      if (Data->Value[i]==entities[e].c) { j+=entities[e].len-1; break; }
      }
    }

  // i=string length, j=new string length
  if (j > i)
    {
    byte *Str;
    Str = (byte*)calloc(j+4,1);
    // Now copy over all new characters
    for(i=j=0; i < Data->ValueLen; i++)
      {
      if (!isprint(Data->Value[i]))
        {
	snprintf((char*)Str+j,7,"&#x%02x;",(Data->Value[i])&0xff);
	j+=6;
	continue;
	}
      for(e=0; entities[e].len; e++)
        {
        if ((i+entities[e].len <= Data->ValueLen) && (Data->Value[i]==entities[e].c))
	  {
	  memcpy(Str+j,entities[e].code,entities[e].len);
	  j+=entities[e].len;
	  break;
	  }
        }
      if (entities[e].len == 0)
        {
	Str[j]=Data->Value[i];
	j++;
	}
      }
    free(Data->Value);
    Data->ValueLen=j;
    Data->Value=Str;
    }
} /* SealXmlEncode() */

/**************************************
 SealHexDecode(): Given a string, convert hex to binary
 NOTE: Invalid or odd-length returns noting.
 **************************************/
void	SealHexDecode	(sealfield *Data)
{
  // Do the decoding inline
  if (!Data || !Data->ValueLen) { return; }

  size_t i,j;
  int c=0,bits=0;
  for(i=j=0; i < Data->ValueLen; i++)
    {
    c <<= 4; bits+=4;
    if (!isxdigit(Data->Value[i])) { j=0; break; } // invalid
    else if (isdigit(Data->Value[i])) { c |= (Data->Value[i]-'0'); }
    else if (isupper(Data->Value[i])) { c |= (Data->Value[i]-'A'+10); }
    else if (islower(Data->Value[i])) { c |= (Data->Value[i]-'a'+10); }
    if (bits >= 8)
	{
	Data->Value[j] = c & 0xff;
	j++;
	bits=0;
	}
    }
  if (bits != 0)
    {
    j=0;
    }
  Data->ValueLen = j;
  Data->Type = 'x';
} /* SealHexDecode() */

/**************************************
 SealHexEncode(): Given binary, convert to hex.
 NOTE: Odd values assume terminating "0".
 Stops at any non-hex values.
 **************************************/
void	SealHexEncode	(sealfield *Data, bool IsUpper)
{
  sealfield *D=NULL;
  char d[3];
  size_t i;

  // Do the decoding inline
  if (!Data || !Data->ValueLen) { return; }

  for(i=0; i < Data->ValueLen; i++)
    {
    if (IsUpper) { snprintf(d,3,"%02X",Data->Value[i]); }
    else { snprintf(d,3,"%02x",Data->Value[i]); }
    D = SealAddTextLen(D,"bin",2,d);
    }

  // Replace inline
  byte *tmp; // swap memory
  tmp = Data->Value;
  Data->Value = D->Value;
  Data->ValueLen = D->ValueLen;
  D->Value = tmp;
  SealFree(D);
  Data->Type = 'c';
} /* SealHexEncode() */

/**************************************
 SealBase64Decode(): Given base64, decode to binary.
 Stops at any non-base64 values.
 **************************************/
void	SealBase64Decode	(sealfield *Data)
{
  BIO *bio, *b64;
  sealfield *D=NULL;
  byte d[16];
  int dlen;

  // Do the decoding inline
  if (!Data || !Data->ValueLen) { return; }

  // Make sure it ends with "=" padding
  while(Data->ValueLen % 4) { Data = SealAddC(Data,Data->Field,'='); }

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_mem_buf(Data->Value,Data->ValueLen);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  while((dlen = BIO_read(bio, d, 16)) > 0) // decode in small chunks
    {
    D = SealAddBin(D,"bin",dlen,d);
    }
  BIO_free_all(bio); // frees memory

  if (!D) { Data->ValueLen=0; }

  // Replace inline
  byte *tmp; // swap memory
  tmp = Data->Value;
  Data->Value = D->Value;
  Data->ValueLen = D->ValueLen;
  D->Value = tmp;
  SealFree(D);
  Data->Type = 'x';
} /* SealBase64Decode() */

/**************************************
 SealBase64Encode(): Given base64, decode to binary.
 Stops at any non-base64 values.
 **************************************/
void	SealBase64Encode	(sealfield *Data)
{
  BIO *bio, *b64;
  BUF_MEM *bptr;

  if (!Data || !Data->ValueLen) { return; }

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(b64,Data->Value,Data->ValueLen);
  (void)BIO_flush(b64);

  BIO_get_mem_ptr(b64, &bptr);
  Data->Value = (byte*)realloc(Data->Value,bptr->length+4);
  Data->ValueLen = bptr->length;
  memset(Data->Value,0,Data->ValueLen+4);
  memcpy(Data->Value, bptr->data, bptr->length);

  BIO_free_all(bio); // frees memory
  Data->Type = 'c';
} /* SealBase64Encode() */

/**************************************
 SealParse(): Parse a SEAL record.
 This will scan the entire input space for any SEAL record,
 and it stops at the first one.
   - Sets ['@RecEnd'] to be the end of the data -- for iterative searches.
   - Sets ['@s'] relative to Offset.
   - If Args is provided, copies over verification parameters.
 Returns: sealfield* containing attributes, or NULL if no record found.
   This looks for the <seal ... /> wrapper.
   This tokenizes each field=value in the wrapper.
   The returns sealfield* holdes each field=value.
   It also holds the position of any signature (s=value)
 Caller must use SealFree().
 NOTE: This is NOT a full XML parser!
 **************************************/
sealfield *	SealParse	(size_t TextLen, const byte *Text, size_t Offset, sealfield *Args)
{
  sealfield *Rec=NULL;
  char *Str;
  char IsXML=0; // 0=not XML, 1=is XML, 2=is XML comment
  int State=0; // finite state machine
  char Quote=0; // if tracking start/stop quotes
  size_t i; // index into data
  uint32_t fs=0,fe=0; // field start and end offsets
  uint32_t vs=0,ve=0; // value start and end offsets
  bool IsBad=false;

  if (!Text || (TextLen < 10)) { return(NULL); }

  for(i=0; i < TextLen; i++)
    {
    // If the parsing doesn't match, reset!
    if (IsBad)
      {
      // Clean up any bad parsing
      if (Rec) { SealFree(Rec); Rec=NULL; }
      IsBad=false;
      State=0;
      }
    //DEBUGPRINT("State[%d]=[%.*s]",State,(int)(TextLen-i),(char*)Text+i);

    // State 0: Looking for "<seal" or "<*:seal" or "<?seal"
    if (State==0)
      {
      // Must begin with "<" or "&lt;"; quick check for speed
      if ((Text[i]!='<') && (Text[i]!='&') && (Text[i]!='!')) { continue; } // nope!

      // "<seal>" or "<seal "
      if ((i+6 < TextLen) && !memcmp(Text+i,"<seal ",6))
        {
	// found a start!
	i+=6;
	State=1;
	IsXML=0;
	continue;
	}

      // "&lt;seal "
      if ((i+9 < TextLen) && !memcmp(Text+i,"&lt;seal ",9))
        {
	// found a start!
	i+=9;
	State=1;
	IsXML=1;
	continue;
	}

      // "<?seal "; XML is case-insensitive
      if ((i+7 < TextLen) && !strncasecmp((const char*)Text+i,"<?seal ",7))
        {
	// found a start!
	i+=7;
	State=1;
	IsXML=2;
	continue;
	}

#if 0
      // Generic: Match any namespace
      // "<*:seal>" or "<*:seal "
      size_t j;
      for(j=i+1; (j+10 < TextLen) && isalnum(Text[j]); j++) { ; }
      if ((Text[j]==':') && (j+10 < TextLen) && !memcmp(Text+j,":seal",5) && strchr("> ",Text[j+5]))
        {
	// found a start!
	//DEBUGPRINT("Found: '%.*s'",(int)(j+6-i),Text+i);
	i=j+5;
	State=1;
	continue;
	}
#endif
      IsBad=true;
      }

    // State 1: Looking for attribute (field=)
    else if (State==1)
      {
      if (isspace(Text[i])) { continue; }
      //DEBUGPRINT("Text: [%.*s]",(int)i,Text);
      if (!IsXML)
	{
	if (Text[i]=='>') { goto Done; } // no more values
	if ((i+1 <= TextLen) && !memcmp("/>",Text+i,2)) { goto Done; } // no more values (self-closing)
	if ((i+1 <= TextLen) && !memcmp("</",Text+i,2)) { goto Done; } // no more values (nested closing)
	if (Text[i]=='<') { i--; IsBad=true; } // bad start; recheck the character
	}
      else if (IsXML==2) // XML comment
	{
	if ((i+1 <= TextLen) && !memcmp("?>",Text+i,2)) { goto Done; } // no more values (self-closing)
	if (Text[i]=='<') { i--; IsBad=true; } // bad start; recheck the character
	if (Text[i]=='>') { IsBad=true; } // bad end
	}
      else // XML encoding
	{
	if ((i+4 <= TextLen) && !memcmp("&gt;",Text+i,4)) { goto Done; }
	if ((i+5 <= TextLen) && !memcmp("/&gt;",Text+i,5)) { goto Done; }
	if ((i+5 <= TextLen) && !memcmp("&lt;/",Text+i,5)) { goto Done; }
	if ((i+4 <= TextLen) && !memcmp("&lt;",Text+i,4)) { i--; IsBad=true; }
	}

      if (!isalpha(Text[i])) { IsBad=true; } // bad start
      fs = i;
      while((i < TextLen) && isalnum(Text[i])) { i++; }
      fe = i;
      if (Text[i]=='=') { State=2; } // found field!
      else { i--; State=0; } // bad attribute
      }

    // State 2: Looking for attribute (value)
    else if (State==2)
      {
      // Value may be quoted
      Quote=0;
      if (strchr("\"'",Text[i])) { Quote=Text[i]; i++; }
      if (IsXML && (i+6 < TextLen) && !memcmp("&quot;",Text+i,6)) { Quote=1; i+=6; }
      // Scan for the end of the string
      vs=i;
      for( ; i < TextLen; i++)
        {
	if (Text[i]=='\\') { i++; } // permit quoting next character.
	else if (!Quote && strchr(" <>",Text[i])) { ve=i; State=3; break; } // found value!
	else if ((Quote!=1) && (Text[i]==Quote)) { ve=i; i++; State=3; break; } // found value!
	else if (Quote==1) // Special case for '&quot;'
	  {
	  if ((i+6 < TextLen) && !memcmp("&quot;",Text+i,6))
	    {
	    ve=i;
	    i+=6;
	    State=3;
	    break;
	    }
	  }
	// Anything else is another character in the value
	}

      // State 3: End of attribute (value)
      if (State==3)
	{
	//DEBUGPRINT("State[%d]=[%.*s]",State,(int)(TextLen-i),(char*)Text+i);
	/*****
	 Field needs to be a null-terminated string.
	 Let's cheat and store it into a sealfield!
	 *****/
	Rec = SealSetTextLen(Rec,"@field",fe-fs,(char*)Text+fs);
	Str = SealGetText(Rec,"@field");

	// Warn if there is a duplicate!
	if (SealSearch(Rec,Str))
	  {
	  printf("WARNING: '%s' redefined.\n",Str);
	  }

	// Check for the signature position and save it
	if (!strcmp(Str,"s"))
	  {
	  Rec = SealSetIindex(Rec,"@s",0,Offset+vs);
	  Rec = SealSetIindex(Rec,"@s",1,Offset+ve);
	  Rec = SealSetIindex(Rec,"@s",2,SealGetIindex(Args,"@s",2)+1); // increment record number

	  if (Args)
	    {
	    Rec = SealCopy2(Rec,"@p",Args,"@s"); // previous '@s' is now '@p'
	    Rec = SealCopy2(Rec,"@dnscachelast",Args,"@dnscachelast"); // use any cached DNS
	    Rec = SealCopy2(Rec,"@public",Args,"@public"); // use any cached DNS
	    Rec = SealCopy2(Rec,"@publicbin",Args,"@publicbin"); // use any cached DNS
	    Rec = SealCopy2(Rec,"dnsfile",Args,"dnsfile"); // use any local dns file
	    }
	  }

	// Store the value
	//DEBUGPRINT("Field[%s]='%.*s'",Str,(int)(ve-vs),Text+vs);
	Rec = SealSetTextLen(Rec,Str,ve-vs,(char*)Text+vs);
	if (Quote != 1) { SealStrDecode(SealSearch(Rec,Str)); } // convert any \c to c
	else if (Quote == 1) { SealXmlDecode(SealSearch(Rec,Str)); } // convert any &code; to utf8
	//DEBUGPRINT("Field[%s] Quote=%d = [%s]",Str,Quote,SealGetText(Rec,Str));

	// Remove temporary storage
	Rec = SealDel(Rec,"@field");

	// Make sure value ends properly
	if (isspace(Text[i])) { State=1; } // look for more attributes
	else if (strchr("<>/",Text[i])) // done!
	  {
	  while((i < TextLen) && (Text[i] != '>')) { i++; }
	  if (Text[i]=='>') { i++; }
	  goto Done; // or "break;"
	  }
	else if (IsXML==2) // XML comment
	  {
	  if ((i+2 <= TextLen) && !memcmp("?>",Text+i,2)) { i+=2; goto Done; } // done!
	  }
	else if (IsXML && i+4 <= TextLen && (!memcmp("&lt;",Text+i,4) || !memcmp("&gt;",Text+i,4))) // done!
	  {
	  while((i+4 <= TextLen) && memcmp("&gt;",Text+i,4)) { i++; }
	  if ((i+4 <= TextLen) && !memcmp("&gt;",Text+i,4)) { i+=4; }
	  goto Done; // or "break;"
	  }
	else { IsBad=true; } // unknown next character
	} // if State==3
      // anything else is bad
      else { i--; IsBad=true; }
      } // if State==2
    // State doesn't exist; Never makes it here; included for completeness
    else { IsBad=true; }
    } // Parse text length

Done:
  if (Rec)
    {
    Rec = SealSetIindex(Rec,"@RecEnd",0,i); // Mark end of the record
    }
  return(Rec);
} /* SealParse() */

