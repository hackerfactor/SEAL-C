/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling DICOM files.
 DICOM is common in the medical community.

 =====
 DICOM begins with a "preamble" (header).
   - A 128 byte comment that is ignored.
   - Then comes the literal "DICM".

 The preamble is followed by a list of data elements.
 Each data element contains:
   Tag
   Value Representation (VR)
   Value Length (VL) (stored in little endian)
   Value Field (VF)

 Each Tag contains two 16-bit values:
    group number
    element number
 E.g., group 0010 is related to the patient information:
    (0010,0010) = Patient Name
    (0010,0020) = Patient ID
 Re: https://dicom.nema.org/medical/dicom/current/output/html/part06.html

 Depending on the VR value, VL may be a 16-bit or 32-bit length,
 or may be an indefinite length that ends with a closing code.
 Ref: https://dicom.nema.org/medical/dicom/current/output/html/part05.html#sect_6.2
 VR values:
   AE = Application entry
   AS = Age string
   AS = Attribute tag
   OB = Other byte
   OD = Other double
   OF = Other float
   OL = Other long
   OV = Other very long
   OW = Other word
   ...

 The tag (fffe,e000) begins encapsilation.
 The tags (fffe,e0dd) and (fffe,e00d) ends a sequence, length is 0x00000000.
 
 16-bit lengths:
   AE, AS, AT, CS, DA, DS, DT, FL, FD, IS, LO, LT, PN, SH, SL, SS, ST, TM, UI, UL, US 

 All others:
   2 bytes are reserved for later definitions.
   Then there's a 32-bit length.

 OB, OD, OF, OL, OV, OW, SQ, UN
   If there's an explicit length, it's 32-bits.
   But if the length is undefined (VL is 0xffffffff) then it contains a series
   of implicit VRs: Tag-VR-VL-VF
   Implicit VR ends with the tag (fffe,e0dd) or (fffe,e00d).

 (Why this complexity? Because consistent parsing is for wimps!)


 For SEAL:
 Scan any explicit ST, LT, and UT fields.
 (Skip an implicit records since they are nested.)

 For encoding: Use one of these VR:
   ST = Short text, up to 1024 characters max
   LT = Long text, up to 10240 characters max
   UT = Unlimited text, up to 0xfffffffe characters

 What Tag?  DICOM specs (section 7.8.1) defines private data elements.
 Ref: https://dicom.nema.org/medical/dicom/current/output/chtml/part05/sect_7.8.html
   - Must be an odd numbered group.
   - Must not be one of the predefined groups.
   - "cea1" is odd and not predefined! Let's use it!
 Before it can be used, it must be defined:
   - If (cea1,0010) is not defined, then define it.
   - Signatures go in (cea1,1001).
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
 _DICOMwalk(): Given a DICOM, walk the structures.
 Evaluate any SEAL or text chunks.
   Data and DataLen are for the current chunk.
   Pos is the absolute start of the chunk relative to the file.
   Mmap is the absolute start of the file.
   Uses '@DICOMcea1' to track if it has the cea1 group reserved.
 **************************************/
sealfield *	_DICOMwalk	(sealfield *Args, mmapfile *Mmap)
{
  size_t Offset=0x84; // skip preface and "DICM" identifier
  int Nest=0; // how deep is the nesting?
  uint16_t Group,Element,VR;
  uint32_t VL; // value length
  bool SkipVL;

#define DEBUGDICOMWALK 0
  Args = SealSetText(Args,"DICOM_ERROR","Overflow"); // assume bad
  
  while(Offset+8 <= Mmap->memsize)
    {
    SkipVL=false;
    Group = readle16(Mmap->mem + Offset); Offset+=2;
    Element = readle16(Mmap->mem + Offset); Offset+=2;
    VR = readbe16(Mmap->mem + Offset); Offset+=2;
    VL = readle16(Mmap->mem + Offset); Offset+=2;
#if DEBUGDICOMWALK
    printf("%*s 0x%lx: (%04x,%04x,%c%c) = ",Nest," ",Offset-8,Group,Element,(VR>>8)&0xff,VR&0xff);
#endif

    // Look for special case tags
    if (Group==0xfffe)
      {
      /*****
       DICOM Ref: 7.5.1
       (fffe,e000) has two possible modes.
       If length is set, then that's the length.
       If the length is 0xffffffff then it's unspecified and ends with e00d or e0dd.
       *****/
      VR=0; Offset-=4; // No VR, no VL; will read VL next.
      if (Element==0xe000) { ; } // start nesting
      else if (Element==0xe00d) { Nest--; } // end delimination
      else if (Element==0xe0dd) { Nest--; } // end sequence
      }

    // Now check for special VL lengths
    if (!SkipVL)
      {
      switch(VR)
	{
	// List of known (consistent) 16-bit data types
	case 0x4145: // AE
	case 0x4153: // AS
	case 0x4154: // AT
	case 0x4353: // CS
	case 0x4441: // DA
	case 0x4453: // DS
	case 0x4454: // DT
	case 0x464c: // FL
	case 0x4644: // FD
	case 0x4953: // IS
	case 0x4c4f: // LO
	case 0x4c54: // LT
	case 0x504e: // PN
	case 0x5348: // SH
	case 0x534c: // SL
	case 0x5353: // SS
	case 0x5354: // ST
	case 0x544d: // TM
	case 0x5549: // UI
	case 0x554c: // UL
	case 0x5553: // US
#if DEBUGDICOMWALK
	  printf("%lu bytes\n",(ulong)VL);
#endif
	  break; // known 16-bit lengths
	default:
	  // Everything else is inconsistent!
	  if (Offset+4 > Mmap->memsize) { return(Args); } // overflow
	  VL = readle32(Mmap->mem + Offset); Offset+=4;
	  if (VL==0xffffffff)
	    {
	    Nest++; VL=0;
#if DEBUGDICOMWALK
	    printf("\n");
#endif
	    }
#if DEBUGDICOMWALK
	  else { printf("%lu bytes\n",(ulong)VL); }
#endif
	  break;
	}
      }
    else { printf("\n"); }

    if (Offset+VL > Mmap->memsize) { return(Args); } // overflow

    // Look for SEAL records
    if ((Group==0xcea1) && (Element==0x0010))
      {
      Args = SealSetText(Args,"@DICOMcea1","true"); // Someone already reserved the space!
      }

    switch(VR)
      {
      case 0x5354: // ST: short text (1024 or shorter)
      case 0x4c54: // LT: long text (10240 or shorter)
      case 0x5554: // UT: 'unlimited' text (up to 0xfffffffe bytes)
	if ((Nest == 0) && (VL > 8)) // must be top-level and big enough
	  {
#if DEBUGDICOMWALK
	  printf("Scanning...\n");
#endif
	  Args = SealVerifyBlock(Args, Offset, Offset+VL, Mmap, NULL);
	  }
	break;
      default: break;
      }

    // On to the next DICOM entry!
    Offset += VL;
    }
#if DEBUGDICOMWALK
  printf("Walk end at 0x%lx vs file end 0x%lx\n",(ulong)Offset,(ulong)Mmap->memsize);
#endif

  Args = SealDel(Args,"DICOM_ERROR"); // not bad!
  return(Args);
} /* _DICOMwalk() */

#pragma GCC visibility pop

/**************************************
 Seal_isDICOM(): Is this file a DICOM?
 Returns: true or false.
 **************************************/
bool	Seal_isDICOM	(mmapfile *Mmap)
{
  if (!Mmap || (Mmap->memsize < 0x84)) { return(false); }
  if (memcmp(Mmap->mem+0x80,"DICM",4)) { return(false); }
  return(true);
} /* Seal_isDICOM() */

/**************************************
 Seal_DICOMsign(): Sign a DICOM.
 Insert a DICOM signature.
 **************************************/
sealfield *	Seal_DICOMsign	(sealfield *Args, mmapfile *MmapIn)
{
  /*****
   Signing a DICOM is almost easy:
   Add the signed block to the end.
   The caveats?
     - Need to reserve the tag space if it's not already reserved.
     - Type (VR) and Length (VL) varies based on the size of the SEAL record.
     - Encoding values for tag and length.
   *****/
  const char *fname;
  char *Opt;
  mmapfile *MmapOut;
  sealfield *rec;
  byte VLlen[4];

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

  // All lengths must be even; add padding as needed
  if (rec->ValueLen % 2)
    {
    Args = SealAddC(Args,"@record",' ');
    rec = SealSearch(Args,"@record");
    }

  // Create the block
  Args = SealSetTextLen(Args,"@BLOCK",0,""); // placeholder

  // Add the tag reservation if necessary
  if (SealGetText(Args,"@DICOMcea1")==NULL) // does it need a reservation
    {
    Args = SealSetBin(Args,"@BLOCK",12,(const byte*)"\xa1\xce\x10\x00LO\x04\x00SEAL"); // reserved group 0xcea1
    }

  // Data type (VR) and length (VL) depends on the record size
  writele32(VLlen,rec->ValueLen);
  if (rec->ValueLen < 1024) // fits in short text!
    {
    Args = SealAddBin(Args,"@BLOCK",6,(const byte*)"\xa1\xc3\x01\x10ST");
    Args = SealAddBin(Args,"@BLOCK",2,VLlen);
    }
  else if (rec->ValueLen < 10240) // fits in long text!
    {
    Args = SealAddBin(Args,"@BLOCK",6,(const byte*)"\xa1\xc3\x01\x10LT");
    Args = SealAddBin(Args,"@BLOCK",2,VLlen);
    }
  else // needs "unlimited" text (very long text)!
    {
    Args = SealAddBin(Args,"@BLOCK",8,(const byte*)"\xa1\xc3\x01\x10UT\x00\x00");
    Args = SealAddBin(Args,"@BLOCK",4,VLlen);
    }

  // Make '@s' relative to block
  SealIncIindex(Args, "@s", 0, SealGetSize(Args,"@BLOCK"));
  SealIncIindex(Args, "@s", 1, SealGetSize(Args,"@BLOCK"));

  // Add record
  Args = SealAddBin(Args,"@BLOCK",rec->ValueLen,rec->Value);
  SealSetType(Args,"@BLOCK",'x');
  
  MmapOut = SealInsert(Args,MmapIn,MmapIn->memsize);
  if (MmapOut)
    {
    // Sign it!
    SealSign(Args,MmapOut,NULL);
    MmapFree(MmapOut);
    }
  
  return(Args);
} /* Seal_DICOMsign() */

/**************************************
 Seal_DICOM(): Process a DICOM.
 Reads every seal signature.
 If signing, add the signature before the IEND tag.
 **************************************/
sealfield *	Seal_DICOM	(sealfield *Args, mmapfile *Mmap)
{
  // Make sure it's a DICOM.
  if (!Seal_isDICOM(Mmap)) { return(Args); }

  Args = _DICOMwalk(Args, Mmap);

  /*****
   Sign as needed
   *****/
  Args = Seal_DICOMsign(Args,Mmap); // Add a signature as needed
  Args = SealDel(Args,"@DICOMcea1"); // no longer needed
  if (SealGetIindex(Args,"@s",2)==0) // no signatures
    {
    printf(" No SEAL signatures found.\n");
    }

  return(Args);
} /* Seal_DICOM() */

