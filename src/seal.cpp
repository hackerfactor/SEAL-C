/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling the parameters data structure.

 C doesn't have dynamic variables, so use these instead.
 For languages with local/global dynamic variables for
 hashes (named arrays; e.g., PHP, JavaScript)
 then these are just a named array indexes.
 ************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "seal.hpp"

#define PAD 4 /* padding to prevent overflow; should not be needed */

int Verbose=0;

/**************************************
 DEBUGhexdump(): Display hexdump of data.
 Strictly for debuggin.
 **************************************/
void	DEBUGhexdump	(size_t DataLen, const byte *Data)
{
  size_t line,i;

  for(line=0; line < DataLen; line+=16)
    {
    fprintf(stderr,"%08x | ",(int)line);
    for(i=0; i < 16; i++)
      {
      if (i==8) { fprintf(stderr," "); }
      if (line+i < DataLen) { fprintf(stderr,"%02x ",Data[line+i]); }
      else { fprintf(stderr,"   "); }
      }
    fprintf(stderr,"| ");
    for(i=0; i < 16; i++)
      {
      if (line+i >= DataLen) { break; }
      if (isspace(Data[line+i])) { fprintf(stderr," "); }
      else if (isprint(Data[line+i])) { fprintf(stderr,"%c",Data[line+i]); }
      else { fprintf(stderr,"."); }
      }
    fprintf(stderr,"\n");
    }
} /* DEBUGhexdump() */

/**************************************
 SealFree(): Free the chain of sealfield records.
 Caller MUST not use vf anymore.
 **************************************/
void	SealFree	(sealfield *vf)
{
  sealfield *vfnext=NULL;

  // iterate over the linked list and free each element.
  while(vf)
    {
    //DEBUGPRINT("Free: [%s] [%s]",vf->Field,vf->Type=='c' ? (char*)vf->Value : "");
    if (vf->Field) { free(vf->Field); }
    if (vf->Value) { free(vf->Value); }
    vfnext = vf->Next;
    free(vf);
    vf = vfnext;
    }
} /* SealFree() */

/**************************************
 SealWalk(): DEBUGGING. Walk the chain of sealfield records.
 **************************************/
void	SealWalk	(sealfield *vf, bool ShowOne)
{
  int num=0;
  size_t i;
  for( ; vf; vf=vf->Next)
    {
    fprintf(stderr,"sealfield[%d]: '%.*s' (type %c, %ld bytes) =",
	num,
	(int)vf->FieldLen, vf->Field,
	vf->Type,
	vf->ValueLen);
    switch(vf->Type)
	{
	case 'c': fprintf(stderr," '%.*s'\n",(int)vf->ValueLen, vf->Value); break;

	case '4':
	  for(i=0; i < vf->ValueLen; i+=sizeof(uint32_t))
	    {
	    fprintf(stderr," %u",((uint*)(vf->Value+i))[0]);
	    }
	  fprintf(stderr,"\n");
	  break;

	case '8':
	  for(i=0; i < vf->ValueLen; i+=sizeof(uint64_t))
	    {
	    fprintf(stderr," %lu",((ulong*)(vf->Value+i))[0]);
	    }
	  fprintf(stderr,"\n");
	  break;

	case 'I':
	  {
	  size_t Val;
	  for(i=0; i < vf->ValueLen; i+=sizeof(size_t))
	    {
	    Val = ((size_t*)(vf->Value+i))[0];
	    fprintf(stderr," %ld",(long)Val);
	    }
	  fprintf(stderr,"\n");
	  }
	  break;

	case 'x': // hex dump (great for debugging binary data)
	  fprintf(stderr,"\n");
	  DEBUGhexdump(vf->ValueLen,vf->Value);
	  break;

	case 'b':
	default:
	  fprintf(stderr," 0x");
	  for(i=0; i < vf->ValueLen; i++)
	    {
	    fprintf(stderr,"%02x",vf->Value[i]);
	    }
	  fprintf(stderr,"\n");
	  break;
	}
    num++;
    if (ShowOne) { break; }
    }
} /* SealWalk() */

/**************************************
 SealSetType(): Change the type character for debugging.
 **************************************/
void	SealSetType	(sealfield *vfhead, const char *Field, const char Type)
{
  sealfield *vf;
  vf = SealSearch(vfhead,Field);
  if (vf) { vf->Type = Type; }
} /* SealSetType() */

/**************************************
 SealCmp(): Compare two fields.
 NOTE: There is a difference between "not defined"
 and "defined as empty".
 **************************************/
int	SealCmp	(sealfield *vfhead, const char *Field1, const char *Field2)
{
  sealfield *vf1, *vf2;
  if (!vfhead) { return(0); } // neither exists == same

  vf1 = SealSearch(vfhead,Field1);
  vf2 = SealSearch(vfhead,Field2);

  // Check if defined
  if (!vf1 && !vf2) { return(0); } // neither exists == same
  if (!vf1) { return(1); } // vf2 > not exist
  if (!vf2) { return(-1); } // vf1 > not exist

  // Check if empty
  if (!vf1->ValueLen && !vf2->ValueLen) { return(0); } // both empty
  if (!vf1->ValueLen) { return(1); } // vf2 > empty
  if (!vf2->ValueLen) { return(-1); } // vf1 > empty

  // Compare!
  int rc;
  size_t M; // minimum length
  M = (vf1->ValueLen < vf2->ValueLen) ? vf1->ValueLen : vf2->ValueLen;
  rc = memcmp(vf1->Value,vf2->Value,M);
  if (rc) { return(rc); }
  // Same value! Check for same length
  if (vf1->ValueLen > vf2->ValueLen) { return(1); } // shortest wins
  if (vf1->ValueLen < vf2->ValueLen) { return(-1); } // shortest wins
  return(0); // SAME!
} /* SealCmp() */

/**************************************
 SealCmp2(): Compare two fields from two different structures.
 NOTE: There is a difference between "not defined"
 and "defined as empty".
 **************************************/
int	SealCmp2	(sealfield *vfhead1, const char *Field1, sealfield *vfhead2, const char *Field2)
{
  sealfield *vf1, *vf2;

  vf1 = SealSearch(vfhead1,Field1);
  vf2 = SealSearch(vfhead2,Field2);

  // Check if defined
  if (!vf1 && !vf2) { return(0); } // neither exists == same
  if (!vf1) { return(1); } // vf2 > not exist
  if (!vf2) { return(-1); } // vf1 > not exist

  // Check if empty
  if (!vf1->ValueLen && !vf2->ValueLen) { return(0); } // both empty
  if (!vf1->ValueLen) { return(1); } // vf2 > empty
  if (!vf2->ValueLen) { return(-1); } // vf1 > empty

  // Compare!
  int rc;
  size_t M; // minimum length
  M = (vf1->ValueLen < vf2->ValueLen) ? vf1->ValueLen : vf2->ValueLen;
  rc = memcmp(vf1->Value,vf2->Value,M);
  if (rc) { return(rc); }
  // Same value! Check for same length
  if (vf1->ValueLen > vf2->ValueLen) { return(1); } // shortest wins
  if (vf1->ValueLen < vf2->ValueLen) { return(-1); } // shortest wins
  return(0); // SAME!
} /* SealCmp() */

/**************************************
 SealAlloc(): Clear and allocate memory in the sealfield chain.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealAlloc	(sealfield *vfhead, const char *Field, size_t ValueLen, const char Type)
{
  sealfield *vf=NULL,*vfp;

  // clear and allocate
  vfp = (sealfield*)calloc(sizeof(sealfield),1); // clear and allocate

  // Set Field
  vfp->FieldLen = strlen(Field);
  vfp->Field = (char*)calloc(vfp->FieldLen+PAD,1); // extra space ensures null termination
  memcpy(vfp->Field,Field,vfp->FieldLen);

  // Set Value
  vfp->Type = Type;
  vfp->ValueLen = ValueLen;
  vfp->Value = (byte*)calloc(ValueLen+PAD,1);

  // Base case: no head so make this the head
  //if (!vfhead) { return(vfp); }

  // Find element to replace
  for(vf=vfhead; vf; vf=vf->Next)
    {
    if (!strcmp(vf->Field,Field)) // if found it
	{
	free(vfp->Field); // already have it; don't keep
	// replace value
	if (vf->Value) { free(vf->Value); }
	vf->ValueLen = ValueLen;
	vf->Value = vfp->Value;
	// no longer need vfp structure
	free(vfp);
	return(vfhead);
	}
    }

  // If it gets here, then nothing to replace; do add!

  // if adding, then append to the start of the chain
  vfp->Next = vfhead;
  return(vfp);
} /* SealAlloc() */

/**************************************
 SealAllocU32(): Clear and allocate memory for uint32_t.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealAllocU32	(sealfield *vfhead, const char *Field, size_t Num)
{
  if (!Field) { return(vfhead); }
  return(SealAlloc(vfhead, Field, Num * sizeof(uint32_t),'4'));
} /* SealAllocU32() */

/**************************************
 SealAllocU64(): Clear and allocate memory for uint64_t.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealAllocU64	(sealfield *vfhead, const char *Field, size_t Num)
{
  if (!Field) { return(vfhead); }
  return(SealAlloc(vfhead, Field, Num * sizeof(uint64_t),'8'));
} /* SealAllocU64() */

/**************************************
 SealAllocI(): Clear and allocate memory for size_t.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealAllocI	(sealfield *vfhead, const char *Field, size_t Num)
{
  if (!Field) { return(vfhead); }
  return(SealAlloc(vfhead, Field, Num * sizeof(size_t),'I'));
} /* SealAllocI() */

/**************************************
 SealCopy(): Copy value from old to new.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealCopy	(sealfield *vfhead, const char *NewField, const char *OldField)
{
  // Idiot checking
  if (!NewField || !OldField || !strcmp(NewField,OldField)) { return(vfhead); }

  sealfield *vfold, *vfnew;
  vfold = SealSearch(vfhead,OldField);
  if (!vfold) { return(SealDel(vfhead,NewField)); } // can't copy if it doesn't exist.

  vfhead = SealDel(vfhead,NewField);
  vfhead = SealAlloc(vfhead,NewField,vfold->ValueLen,vfold->Type);
  vfnew = SealSearch(vfhead,NewField);
  if (!vfnew) { return(vfhead); } // should never fail

  memcpy(vfnew->Value,vfold->Value,vfold->ValueLen);
  return(vfhead);
} /* SealCopy() */

/**************************************
 SealCopy2(): Copy value from from Field1 to Field2
 Returns: head of new sealfield chain.
 **************************************/
sealfield *	SealCopy2	(sealfield *vfhead2, const char *Field2, sealfield *vfhead1, const char *Field1)
{
  // Idiot checking
  if (!vfhead1 || !Field1) { return(vfhead2); }

  sealfield *vf1, *vf2;
  vf1 = SealSearch(vfhead1,Field1);
  if (!vf1) { return(SealDel(vfhead2,Field2)); } // can't copy if it doesn't exist.

  vfhead2 = SealDel(vfhead2,Field2);
  vfhead2 = SealAlloc(vfhead2,Field2,vf1->ValueLen,vf1->Type);
  vf2 = SealSearch(vfhead2,Field2);
  if (!vf2) { return(vfhead2); } // should never fail

  memcpy(vf2->Value,vf1->Value,vf1->ValueLen);
  return(vfhead2);
} /* SealCopy2() */

/**************************************
 SealClone(): Copy entire sealfield chain to a new chain.
 Returns: head of new sealfield chain.
 THIS IS RECURSIVE.
 **************************************/
sealfield *	SealClone	(sealfield *src)
{
  sealfield *dst=NULL,*s,*d;

  for(s=src; s; s=s->Next)
    {
    d = SealCopy2(NULL,s->Field,s,s->Field);
    d->Next = dst;
    dst = d;
    }
  return(dst);
} /* SealClone() */

/**************************************
 SealMove(): Rename a field.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealMove	(sealfield *vfhead, const char *NewField, const char *OldField)
{
  // Idiot checking
  if (!NewField || !OldField || !strcmp(NewField,OldField)) { return(vfhead); }

  sealfield *vfp;
  vfp = SealSearch(vfhead,NewField);
  if (vfp) { return(SealDel(vfhead,NewField)); } // remove new location

  vfp = SealSearch(vfhead,OldField);
  if (!vfp) { return(vfhead); } // nothing to move!
  vfp->FieldLen = strlen(NewField);
  vfp->Field = (char*)calloc(vfp->FieldLen+PAD,1); // extra space ensures null termination
  memcpy(vfp->Field,NewField,vfp->FieldLen);

  return(vfhead);
} /* SealMove() */

/**************************************
 SealSetBin(): Insert binary data into the sealfield chain.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealSetBin	(sealfield *vfhead, const char *Field, size_t ValueLen, const byte *Value)
{
  sealfield *vf=NULL;

  if (!Field) { return(vfhead); }
  vfhead = SealAlloc(vfhead,Field,ValueLen,'b');
  if (!vfhead) { return(vfhead); }
  if (!Value) { ValueLen=0; }

  // Find element!
  for(vf=vfhead; vf; vf = vf->Next)
    {
    if (!strcmp(vf->Field,Field)) { break; } // if found it
    }

  if (!vf) { return(vfhead); } // never happens since SealAlloc() was called.

  // Store value
  vf->Type='b';
  if (Value)
    {
    memcpy(vf->Value,Value,ValueLen);
    }
  return(vfhead);
} /* SealSetBin() */

/**************************************
 SealSetText(): Put text in the sealfield chain.
 As text, it allocates extra bytes to ensure null termination.
 Returns: head of sealfield chain.
 NOTE: Caller must ensure that Value has ValueLen bytes!
 **************************************/
sealfield *	SealSetTextLen	(sealfield *vfhead, const char *Field, size_t ValueLen, const char *Value)
{
  sealfield *vf=NULL;

  if (!Field) { return(vfhead); }
  vfhead = SealAlloc(vfhead,Field,ValueLen,'c'); // add in null padding
  if (!vfhead) { return(vfhead); }

  // Find element!
  for(vf=vfhead; vf; vf = vf->Next)
    {
    if (!strcmp(vf->Field,Field)) { break; } // if found it
    }

  if (!vf) { return(vfhead); } // never happens since SealAlloc() was called.

  // Store value
  vf->Type='c';
  if (ValueLen) { memcpy(vf->Value,Value,ValueLen); }
  return(vfhead);
} /* SealSetTextLen() */

/**************************************
 SealSetText(): Put text in the sealfield chain.
 As text, it allocates extra bytes to ensure null termination.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealSetText	(sealfield *vfhead, const char *Field, const char *Value)
{
  size_t ValueLen=0;
  if (Value) { ValueLen=strlen(Value); }
  return(SealSetTextLen(vfhead,Field,ValueLen,Value));
} /* SealSetText() */

/**************************************
 SealAddTextLen(): Append text to the sealfield chain.
 As text, it allocates extra bytes to ensure null termination.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealAddTextLen	(sealfield *vfhead, const char *Field, size_t ValueLen, const char *Value)
{
  sealfield *vf=NULL;
  size_t OldValueLen;

  // Base case: nothing to add
  if (!Field || !Value || !Value[0]) { return(vfhead); }

  // Base case: nothing in the list
  if (!vfhead) { return(SealSetText(vfhead,Field,Value)); }

  // Find the field if it exists
  for(vf=vfhead; vf; vf = vf->Next)
    {
    if (!strcmp(vf->Field,Field)) { break; } // if found it
    }

  // If not found, then set it!
  if (!vf) { return(SealSetText(vfhead,Field,Value)); }

  // Found it! Reallocate space and append.
  if (ValueLen > 0)
    {
    OldValueLen = vf->ValueLen;
    vf->ValueLen += ValueLen;
    vf->Value = (byte*)realloc(vf->Value,vf->ValueLen+PAD); // extra space ensures null termination
    memcpy(vf->Value+OldValueLen,Value,ValueLen); // append
    memset(vf->Value+OldValueLen+ValueLen,0,PAD); // clear remaining space
    }
  return(vfhead);
} /* SealAddTextLen() */

/**************************************
 SealAddText(): Append text to the sealfield chain.
 As text, it allocates extra bytes to ensure null termination.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealAddText	(sealfield *vfhead, const char *Field, const char *Value)
{
  if (!Value) { return(vfhead); }
  return(SealAddTextLen(vfhead, Field, strlen(Value), Value));
} /* SealAddText() */

/**************************************
 SealAddC(): Append one character to the sealfield chain.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealAddC	(sealfield *vfhead, const char *Field, const char Value)
{
  return(SealAddTextLen(vfhead, Field, 1, &Value));
} /* SealAddC() */

/**************************************
 SealAddI(): Append a size_t to the sealfield chain.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealAddI	(sealfield *vfhead, const char *Field, const size_t Value)
{
  sealfield *f;
  vfhead = SealAddBin(vfhead, Field, sizeof(size_t), (const byte*)(&Value));
  f = SealSearch(vfhead,Field);
  if (f) { f->Type='I'; }
  return(vfhead);
} /* SealAddI() */

/**************************************
 SealAddTextPad(): Append padding text.
 If Pad==NULL, then fill with spaces.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealAddTextPad	(sealfield *vfhead, const char *Field, size_t PadLen, const char *Pad)
{
  if (PadLen < 1) { return(vfhead); }

  sealfield *vf=NULL;
  vf = SealSearch(vfhead,Field);
  if (!vf)
    {
    vfhead = SealAlloc(vfhead,Field,0,'c');
    vf = SealSearch(vfhead,Field);
    }
  if (!vf) { return(vfhead); } // should never happen

  // Append padding
  vf->Value = (byte*)realloc(vf->Value,vf->ValueLen+PadLen+PAD);
  memset(vf->Value+vf->ValueLen,' ',PadLen);
  memset(vf->Value+vf->ValueLen+PadLen,0,PAD); // clear extra space

  // Set Padding; if the padding is too short then repeat!
  if (Pad && Pad[0])
    {
    size_t pi,po;
    for(pi=po=0; po < PadLen; po++,pi++)
      {
      if (!Pad[pi]) { pi=0; }
      vf->Value[vf->ValueLen + po] = Pad[pi];
      }
    }
  vf->ValueLen += PadLen;
  return(vfhead);
} /* SealAddTextPad() */

/**************************************
 SealAddBin(): Append binary data in the sealfield chain.
 Returns: head of sealfield chain.
 **************************************/
sealfield *	SealAddBin	(sealfield *vfhead, const char *Field, size_t ValueLen, const byte *Value)
{
  sealfield *vf=NULL;
  size_t OldValueLen;

  // Base case: nothing to add
  if (!Field || !Value || (ValueLen == 0)) { return(vfhead); }

  // Base case: nothing in the list
  if (!vfhead) { return(SealSetBin(vfhead,Field,ValueLen,Value)); }

  // Find the field if it exists
  for(vf=vfhead; vf; vf = vf->Next)
    {
    if (!strcmp(vf->Field,Field)) { break; } // if found it
    }

  // If not found, then set it!
  if (!vf) { return(SealSetBin(vfhead,Field,ValueLen,Value)); }

  // Found it! Reallocate space and append.
  OldValueLen = vf->ValueLen;
  vf->ValueLen += ValueLen;
  vf->Value = (byte*)realloc(vf->Value,vf->ValueLen+PAD); // extra space ensures null termination
  memcpy(vf->Value+OldValueLen,Value,ValueLen); // append
  memset(vf->Value+OldValueLen+ValueLen,0,PAD); // clear remaining space
  return(vfhead);
} /* SealAddBin() */

/**************************************
 SealSearch(): Find a field in the chain of sealfield records.
 Returns: sealfield* on match, NULL of missed.
 **************************************/
sealfield *	SealSearch	(sealfield *vf, const char *Field)
{
  size_t FieldLen;
  sealfield *vfp; // sealfield pointer into the linked list

  if (!Field || !vf) { return(NULL); } // idiot checking

  FieldLen = strlen(Field);

  // Fine the name!
  for(vfp=vf; vfp; vfp=vfp->Next)
    {
    if (!vfp->FieldLen && !FieldLen) { return(vfp); } // same zero length
    if ((vfp->FieldLen == FieldLen) && // same length
	!memcmp(vfp->Field, Field, FieldLen) ) // same value
	{ return(vfp); }
    }

  // Not found!
  return(NULL);
} /* SealSearch() */

/**************************************
 SealDel(): Delete a single element (if it exists)
 Returns: New head.
 **************************************/
sealfield *	SealDel	(sealfield *vfhead, const char *Field)
{
  sealfield *vf, *vfn, *vfp;

  // Base case: Nothing to search
  if (!vfhead || !Field) { return(vfhead); }

  // There should only be one element with this Field.
  // But just in case, check for duplicates!

  // Base case: Want to delete head (may appear multiple times?)
  while(vfhead && !strcmp(vfhead->Field,Field))
    {
    vf = vfhead->Next;
    free(vfhead->Field);
    free(vfhead->Value);
    free(vfhead);
    vfhead = vf;
    }

  // Search for element to delete
  if (vfhead)
    {
    vfp=vfhead;
    for(vf=vfhead; vf && vf->Next; vf = vf->Next)
      {
      if (!strcmp(vf->Next->Field,Field))
        {
        vfn = vf->Next;
        free(vfn->Field);
        free(vfn->Value);
        vf->Next = vfn->Next;
        free(vfn);
	vf=vfp;
        }
      else { vfp=vf; }
      }
    }

  return(vfhead);
} /* SealDel() */

/**************************************
 SealGetSize(): Find a field in the chain of sealfield records.
 Returns: length of data (0=no data, same as not found)
 **************************************/
size_t	SealGetSize	(sealfield *vfhead, const char *Field)
{
  sealfield *vf;

  if (!vfhead || !Field) { return(0); }
  vf = SealSearch(vfhead,Field);
  if (!vf) { return(0); }
  return(vf->ValueLen);
} /* SealGetSize() */

/**************************************
 SealGetText(): Find a field in the chain of sealfield records.
 Returns: value as char* on match, NULL if missed.
 **************************************/
char *	SealGetText	(sealfield *vfhead, const char *Field)
{
  sealfield *vf;

  if (!vfhead || !Field) { return(NULL); }
  vf = SealSearch(vfhead,Field);
  if (!vf) { return(NULL); }
  return( (char*)(vf->Value) );
} /* SealGetText() */

/**************************************
 SealGetGarray(): Generic (if this were C++, this would be a template.)
 Find a field in the chain of sealfield records.
 Caller must ensure that it was allocated using AllocU32.
 Returns: value as byte* on match, NULL if missed.
 **************************************/
byte *	SealGetGarray	(sealfield *vfhead, const char *Field)
{
  sealfield *vf;

  if (!vfhead || !Field) { return(NULL); }
  vf = SealSearch(vfhead,Field);
  if (!vf) { return(NULL); }
  return(vf->Value);
} /* SealGetGarray() */

/**************************************
 SealSetGindex(): Generic (if this were C++, this would be a template.)
 Find a field in the chain of sealfield records.
 Sets the index to the value.
 Returns: new vfhead.
 **************************************/
sealfield *	SealSetGindex	(sealfield *vfhead, const char *Field, char Type, size_t Size, int Index, const void *Value)
{
  sealfield *vf;

  if (!vfhead || !Field || (Size <= 0)) { return(NULL); }
  vf = SealSearch(vfhead,Field);
  if (!vf) // if it doesn't exist, then create it.
    {
    vfhead = SealAlloc(vfhead,Field,(Index+1)*Size,Type);
    vf = SealSearch(vfhead,Field);
    if (!vf) { return(NULL); } // should never happen
    }

  // If need more indexes...
  if (Index*Size + Size > vf->ValueLen)
    {
    size_t OldValueLen;
    OldValueLen = vf->ValueLen;
    vf->ValueLen = (Index+1)*Size;
    vf->Value = (byte*)realloc(vf->Value,vf->ValueLen+PAD); // extra space ensures null termination
    memset(vf->Value+OldValueLen, 0, (vf->ValueLen - OldValueLen) +PAD); // clear new space
    }

  // Store new value
  vf->Type=Type;
  memcpy(vf->Value + (Index*Size), Value, Size);
  return(vfhead);
} /* SealSetGindex() */

/***** Wrappers from Generic to Specific *****/
sealfield *	SealSetU32index	(sealfield *vfhead, const char *Field, int Index, uint32_t Value)
{
  return(SealSetGindex(vfhead,Field,'4',sizeof(uint32_t),Index,&Value));
} /* SealSetU32index() */

sealfield *	SealSetU64index	(sealfield *vfhead, const char *Field, int Index, uint64_t Value)
{
  return(SealSetGindex(vfhead,Field,'8',sizeof(uint64_t),Index,&Value));
} /* SealSetU64index() */

sealfield *	SealSetIindex	(sealfield *vfhead, const char *Field, int Index, size_t Value)
{
  return(SealSetGindex(vfhead,Field,'I',sizeof(size_t),Index,&Value));
} /* SealSetIindex() */

sealfield *	SealSetCindex	(sealfield *vfhead, const char *Field, int Index, const char Value)
{
  return(SealSetGindex(vfhead,Field,'c',1,Index,&Value));
} /* SealSetCindex() */

/**************************************
 SealGetGindex(): Generic (if this were C++, this would be a template.)
 Find a field in the chain of sealfield records.
 Returns: value as char on match, 0 if missed.
 NOTE: 0 is same as not found.
 **************************************/
byte *	SealGetGindex	(sealfield *vfhead, const char *Field, size_t Size, int Index)
{
  sealfield *vf;
  int MaxIndex;

  if (!vfhead || !Field) { return(NULL); }
  vf = SealSearch(vfhead,Field);
  if (!vf) { return(NULL); }

  MaxIndex = vf->ValueLen / Size;
  if (Index < MaxIndex) { return(vf->Value + Index*Size); }
  return(NULL);
} /* SealGetGindex() */

/***** Wrappers from Generic to Specific *****/
uint32_t	SealGetU32index	(sealfield *vfhead, const char *Field, int Index)
{
  uint32_t *v;
  v = (uint32_t*)SealGetGindex(vfhead,Field,sizeof(uint32_t),Index);
  if (!v) { return(0); }
  return(v[0]);
}

uint64_t	SealGetU64index	(sealfield *vfhead, const char *Field, int Index)
{
  uint64_t *v;
  v = (uint64_t*)SealGetGindex(vfhead,Field,sizeof(uint64_t),Index);
  if (!v) { return(0); }
  return(v[0]);
}

size_t	SealGetIindex	(sealfield *vfhead, const char *Field, int Index)
{
  size_t *v;
  v = (size_t*)SealGetGindex(vfhead,Field,sizeof(size_t),Index);
  if (!v) { return(0); }
  return(v[0]);
}

char	SealGetCindex	(sealfield *vfhead, const char *Field, int Index)
{
  char *v;
  v = (char*)SealGetGindex(vfhead,Field,1,Index);
  if (!v) { return(0); }
  return(v[0]);
}

/**************************************
 SealIncIindex(): Find an Iindex and increment the value.
 **************************************/
sealfield *	SealIncIindex	(sealfield *vfhead, const char *Field, int Index, size_t IncValue)
{
  size_t v;
  v = SealGetIindex(vfhead,Field,Index);
  v += IncValue;
  return(SealSetGindex(vfhead,Field,'I',sizeof(size_t),Index,&v));
} /* SealIncIindex() */

/**************************************
 SealGetBin(): Find a field in the chain of sealfield records.
 Returns: value as byte* on match, NULL if missed.
 **************************************/
byte *	SealGetBin	(sealfield *vfhead, const char *Field)
{
  sealfield *vf;

  if (!vfhead || !Field) { return(NULL); }
  vf = SealSearch(vfhead,Field);
  if (!vf) { return(NULL); }
  return( (byte*)(vf->Value) );
} /* SealGetBin() */

/**************************************
 SealParmCheck(): Check for sane input parameters.
 **************************************/
sealfield *	SealParmCheck	(sealfield *Args)
{
  sealfield *vf;
  uint16_t u16=0;
  char QuoteChar;
  unsigned int i;

  // Rename long paramters to short
  Args = SealCopy(Args,"da","digestalg");
  Args = SealDel(Args,"digestalg");
  Args = SealCopy(Args,"ka","keyalg");
  Args = SealDel(Args,"keyalg");

  // Check parameters
  for(vf=Args; vf; vf=vf->Next)
    {
    if (vf->Type != 'c') { continue; }

    // All parameters: Printable and no mixed quotes
    QuoteChar=0;
    for(i=0; i < vf->ValueLen; i++)
      {
      if (strchr("'\"",vf->Value[i]))
	{
	if (!QuoteChar) { QuoteChar=vf->Value[i]; }
	else if (vf->Value[i] == QuoteChar) { ; }
	else
	  {
	  fprintf(stderr," ERROR: Invalid parameter: '%.*s' value contains mixed quotes.\n",
		(int)vf->FieldLen, vf->Field);
	  exit(1);
	  }
	}
      else if (isalnum(vf->Value[i]) || ispunct(vf->Value[i])) { ; }
      else if (vf->Value[i] == ' ') { ; }
      else
	  {
	  fprintf(stderr," ERROR: Invalid parameter: '%.*s' value contains an invalid character.\n",
		(int)vf->FieldLen, vf->Field);
	  exit(1);
	  }
      }

    // Some parameters must be positive integers
    if ( ((vf->FieldLen==4) && !memcmp(vf->Field,"seal",4)) ||
         ((vf->FieldLen==7) && !memcmp(vf->Field,"keybits",7))
       )
	{
	u16=0;
	for(i=0; i < vf->ValueLen; i++)
	  {
	  if (!isdigit(vf->Value[i]))
	    {
	    fprintf(stderr," ERROR: Invalid parameter: '%.*s' value is not numeric.\n",
		(int)vf->FieldLen, vf->Field);
	    exit(1);
	    }
	  u16=u16*10 + (vf->Value[i] - '0');
	  }
	}

    // Value already checked and 'u16' already loaded with the value
    if ((vf->FieldLen==7) && !memcmp(vf->Field,"keybits",7))
      {
      // must be power of 2: 64 or larger
      if (u16 < 64)
        {
	fprintf(stderr," ERROR: Invalid parameter: '%.*s' value is too small (at least 64).\n",
		(int)vf->FieldLen, vf->Field);
	exit(1);
	}
      else if (u16 & (u16-1)) // power of 2?
        {
	fprintf(stderr," ERROR: Invalid parameter: '%.*s' value is not a power of 2.\n",
		(int)vf->FieldLen, vf->Field);
	exit(1);
	}
      }

    // Value already checked and 'u16' already loaded with the value
    if ((vf->FieldLen==2) && !memcmp(vf->Field,"ka",2))
      {
      if (!strcmp((char*)vf->Value,"rsa")) { ; } // supported
      // else if (!strcmp((char*)vf->Value,"ed25519")) { ; } // supported
      else if (!strcmp((char*)vf->Value,"ec")) // supported
	{
	Args = SealSetText(Args,"ka","ec");
	}
      // else: assume it's some kind of EC
      }

    // kv, uid: [A-Za-z0-9.+/-]
    if ((vf->FieldLen==2) && !memcmp(vf->Field,"kv",2))
	{
	for(i=0; i < vf->ValueLen; i++)
	  {
	  if (!isalnum(vf->Value[i]) && !strchr(".+/-",vf->Value[i]))
	    {
	    fprintf(stderr," ERROR: Invalid parameter: '%.*s' value contains invalid characters.\n",
		(int)vf->FieldLen, vf->Field);
	    exit(1);
	    }
	  }
	}
    } // foreach Args

  return(Args);
} /* SealParmCheck() */

