/************************************************
 SEAL: implemented in C
 See LICENSE

 Processing ext settings.
  exta=   :: algorithim to use for encoding/ was used
  extd.label=   :: computed digest in exta format
  ext.label=    :: path to file for calculating the digest
  ext=    :: When encoding, directory to recursively glob

 Lots of conditionals:

 When encoding:
  For each ext.label: compute extd.label
  If ext: recursively glob files and compute extd.label.
    Sets 'label' to be a unique number (1,2,3...)
    DO NOT process the file being processed.
  In both cases:
    ONLY process files.
    NO absolute paths, initial "../" or "/../".
    Error if the file is inaccessible or block/pipe/non-file.

 When decoding:
  Let command-line --ext.label overwrite any values from the SEAL record.
  Possible states:
    Error: The path violates the definitions (absolute or upward traversal).
    Inaccessible: ext.label defined, but the file cannot be checked.
    Missing: ext.label defined, but the file does not exist.
    Unvalidated: ext.label defined and the file exists, but no corresponding extd.label.
    Matched: ext.label exists and extd.label digest matched.
    Mismatched: ext.label exists and extd.label digest did not match.
    Unknown: extd.label exists but no corresponding ext.label.

  If the SEAL signature fails, then include a warning:
   Warning: SEAL signature is invalid. External files are unverifiable.
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <glob.h> // for glob()

#include "seal.hpp"
#include "files.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"

/**************************************
 _FileLegal(): Is the filename permitted?
 Forbid anything unsafe, even if the file system
 permits it.
 Returns: true=safe, false=unsafe
 **************************************/
bool	_FileLegal	(const char *S)
{
  int n;
  if (!S && !S[0]) { return(false); }
  for(n=0; S[n]; n++)
    {
    // Reject invalid UTF8
    if ((S[n] < 32) || (S[n] == 127)) { return(false); }
    // Reject any shell or XML exploits
    if (strchr("\\|:<>[]*?$&;\"'`",S[n]) != NULL) { return(false); }
    }
  /*****
   At this point, it's valid for a path.
   Yes, the UTF8 could still be invalid.
   However, invalid will fail when fstat/fopen is called.
   *****/
  return(true);
} /* _FileLegal() */

/**************************************
 _SealExtGetRecurse(): Recursively find all files
 and generate ext.label and extd.label.
 It recurses from Args['@extdir'].
 THIS IS RECURSIVE!
 **************************************/
sealfield *	_SealExtGetRecurse	(sealfield *Args, bool *HasExt,
					 uint32_t *n, int BufSize, char *Buf,
					 char *Exclude1, char *Exclude2)
{
  char *S;
  glob_t G;
  int rc, PathLen;
  size_t g;
  char *RealPathGlob=NULL;
  sealfield *vf;

  S = SealGetText(Args,"@extdir");
  if (!S) { return(Args); } // should never happen

  // Check for basic file regex!
  if (strchr(S,'*') || strchr(S,'?') || strchr(S,'[') || strchr(S,']'))
    {
    rc = glob(SealGetText(Args,"@extdir"),0,NULL,&G);
    if (!rc)
      {
      // Iterate over results
      for(g=0; g < G.gl_pathc; g++)
	{
	// Reset path add recurse!
	// Glob ignores all .files! (Good!)
	// Glob returns entire path, not just the filename. (Good!)
	if (!_FileLegal(G.gl_pathv[g])) { continue; } // no recursive regex!

	// Don't process the source file as an ext
	if (Exclude1 || Exclude2)
	  {
	  RealPathGlob = realpath(G.gl_pathv[g],NULL);
	  if (Exclude1 && RealPathGlob && !strcmp(Exclude1,RealPathGlob))
	    {
	    free(RealPathGlob);
	    continue;
	    }
	  if (Exclude2 && RealPathGlob && !strcmp(Exclude2,RealPathGlob))
	    {
	    free(RealPathGlob);
	    continue;
	    }
	  free(RealPathGlob);
	  }

	Args = SealSetText(Args,"@extdir",G.gl_pathv[g]);
	Args = _SealExtGetRecurse(Args,HasExt,n,BufSize,Buf,Exclude1,Exclude2);
	}
      globfree(&G);
      }
    } // if regex
  else if (!_FileLegal(S)) { ; } // skip illegal characters
  else if (SealIsReadable(S,false)) // it's a file!
    {
    // Find the first available automatic index
    for( ; n[0] < 0xffffff00; n[0]++)
      {
      snprintf(Buf,BufSize,"extd.%u",n[0]); // convert number to extd.label
      if (SealSearch(Args,Buf)) { continue; } // found unused index! Keep seeking
      Args=SealDigestFile(Args,S,"exta",Buf,"@exterror");
      if (SealSearch(Args,Buf)) // found one!
	{
	snprintf(Buf,BufSize,"ext.%u",n[0]); // convert number to ext.label
	Args=SealSetText(Args,Buf,S);
	n[0]++;
	HasExt[0]=true;
	}
      return(Args);
      }
    } // if IsFile
  else if (SealIsDir(S,false)) // it's a directory!
    {
    PathLen = strlen(S);
    Args = SealAddText(Args,"@extdir","/*");
    rc = glob(SealGetText(Args,"@extdir"),0,NULL,&G);
    if (!rc) // glob worked!
      {
      // Iterate over results
      for(g=0; g < G.gl_pathc; g++)
	{
	// Reset path add recurse!
	// Glob ignores all .files! (Good!)
	// Glob returns entire path, not just the filename. (Good!)
	if (!_FileLegal(G.gl_pathv[g])) { continue; } // no recursive regex!

	// Don't process the source file as an ext
	if (Exclude1 || Exclude2)
	  {
	  bool IsSkip=false;
	  RealPathGlob = realpath(G.gl_pathv[g],NULL);
	  if (RealPathGlob)
	    {
	    if (Exclude1 && !strcmp(Exclude1,RealPathGlob)) { IsSkip=true; }
	    else if (Exclude2 && !strcmp(Exclude2,RealPathGlob)) { IsSkip=true; }
	    free(RealPathGlob);
	    if (IsSkip) { continue; }
	    }
	  }

	Args = SealSetText(Args,"@extdir",G.gl_pathv[g]);
	Args = _SealExtGetRecurse(Args,HasExt,n,BufSize,Buf,Exclude1,Exclude2);
	}
      globfree(&G);
      }

    /*****
     Put it back: Truncate path to remove the added directory item.
     *****/
    vf = SealSearch(Args,"@extdir");
    memset(vf->Value+PathLen, 0, vf->ValueLen - PathLen);
    vf->ValueLen = PathLen;
    } // if IsDir

  // else: Not file and not dir? Ignore!

  return(Args);
} /* _SealExtGetRecurse() */

/**************************************
 SealExtGet(): Compute the extd records!
 Searches for any ext.label, then recursively searches for any ext=dir
 Permits @extd.label to overwrite extd.label.
 Returns: updated Args
 **************************************/
sealfield *	SealExtGet	(sealfield *Args)
{
  sealfield *vf,*vextd;
  char *RealPathSource, *RealPathSidecar;
  char *S;
  bool HasExt=false;

  /*****
   When including files via glob, skil the file that
   contains the SEAL signature. (Can't sign while writing!)
   That's either the sidecar or SourceMedia.
   *****/
  RealPathSource = realpath(SealGetText(Args,"@SourceMedia"),NULL);
  RealPathSidecar = SealGetText(Args,"sidecar");
  if (RealPathSidecar) { RealPathSidecar = realpath(RealPathSidecar,NULL); }

  /* Scan for any @ext.label and move it to ext.label */
  for(vf=Args; vf; vf=vf->Next)
    {
    if (!strncmp(vf->Field,"@ext.",5)) // found ext.
      {
      Args = SealDel(Args,"@extdfield");
      Args = SealSetText(Args,"@extdfield","@extd.");
      Args = SealAddText(Args,"@extdfield",vf->Field+5);
      S = SealGetText(Args,"@extdfield"); // name is "@extd.label"
      vextd = SealSearch(Args,S); // Does @extd.label exist?
      if (vextd) // override exists!
	{
	/*****
	 Do not check if the value is valid!
	 If the user wants to supply crap via --extd.label, let them!
	 Crap will fail to validate.
	 Move value from @extd.label to extd.label

	 Allow a blank value, like --extd.label='' to mean "No checksum."
	 Skip if there is no value (just check if it exists)
	 *****/
	Args=SealSetText(Args,(const char*)vf->Field+1,(const char*)vf->Value);
	if (vextd->ValueLen && vextd->Value[0])
	  {
	  Args = SealMove(Args,S+1,S); // move over the value.
	  }
	HasExt=true;
	}
      else if (!_FileLegal(S)) // bad filename!
	{
	// User supplied it, so send it back to the user.
	printf(" Error: Bad filename: %s\n",S);
	}
      else
	{
	// Generate the digest.
	Args=SealDigestFile(Args,(const char*)vf->Value,"exta",S+1,"@exterror");
	S = SealGetText(Args,S+1);
	if (S)
	  {
	  Args=SealSetText(Args,(const char*)vf->Field+1,(const char*)vf->Value);
	  HasExt=true;
	  }
	else // failed to get digest! @exterror must be set!
	  {
	  printf(" %s\n",SealGetText(Args,"@exterror"));
	  }
	}
      } // if @ext.
    } // foreach Args

  // Scan for any extd.label without an ext.label
  for(vf=Args; vf; vf=vf->Next)
    {
    if (!strncmp(vf->Field,"@extd.",6) && vf->ValueLen && vf->Value[0]) // found extd.
      {
      // Move value from @extd.label to extd.label
      Args=SealMove(Args,vf->Field+1,vf->Field); // move over the value.
      HasExt=true;
      }
    } // foreach Args

  // Process any glob directories!
  S = SealGetText(Args,"ext");
  if (S && S[0]) // if at least one character exists...
    {
    // S may be a ";" list of paths
    uint32_t i,n=1;
    char Buf[20]; // for storing "@extd.####: 20 should be overkill
    while(S[0])
      {
      if (S[0]=='/') { S++; } // skip initial slashes
      if (!strncmp(S,"./",2)) { S+=2; } // skip initial ./
      if (!strncmp(S,",./",3)) { S+=3; } // skip initial ../
      // Find string length: EOL or ';'
      for(i=0; S[i] && (S[i]!=';'); i++) { ; }
      S[i]='\0'; // ensure EOL
      if (i > 0)
	{
	Args = SealSetText(Args,"@extdir",S);
	Args = _SealExtGetRecurse(Args,&HasExt,&n,20,Buf,RealPathSource,RealPathSidecar);
	}
      S+=i+1; // Jump to next string
      } // while parsing ext
    } // if ext

  // clean up
  if (RealPathSource) { free(RealPathSource); }
  if (RealPathSidecar) { free(RealPathSidecar); }
  Args=SealDel(Args,"ext"); // no longer needed
  Args=SealDel(Args,"@extdir");
  Args=SealDel(Args,"@extdfield");
  Args=SealDel(Args,"@exterror");
  if (!HasExt) { Args=SealDel(Args,"exta"); } // only required when ext is used
  return(Args);
} /* SealExtGet() */

/**************************************
 SealExtVerify(): Check every ext/extd record.
 Sends results to stdout!
 Returns: 0 on success, else number of files not verified.
 **************************************/
int	SealExtVerify	(sealfield *Args, bool IsValid)
{
  /*****
   Possible states:
     Error: The path violates the definitions (absolute or upward traversal).
     Missing: The `ext.label` is defined, but the file does not exist.
     Inaccessible: The `ext.label` file is defined, but the file cannot be checked.
       Bad permissions.
     Present: `ext.label` defined, file exists, but no corresponding `extd.label`
     Matched: `ext.label` exists and `extd.label` digest matched.
     Mismatched: `ext.label` exists and `extd.label` digest did not match.
     Unknown: `extd.label` exists but there is no corresponding `ext.label`.
   *****/
  int NotValidated=0, UnknownCount=0;
  sealfield *vf,*ext,*extd,*extdcmp;
  sealfield *Processed=NULL;
  char *exta;
  bool First=true;

  Processed = SealCopy2(Processed,"exta",Args,"exta");
  exta = SealGetText(Processed,"exta");

  // Process every ext/extd
  // Check the Processed list for which ones are completed.
  for(vf=Args; vf; vf=vf->Next)
    {
    ext=extd=NULL;

    // Search for anything not already processed...
    if (!strncmp(vf->Field,"ext.",4) && // if "ext."
	!SealSearch(Processed,vf->Field) ) // not processed
      {
      ext = vf;
      // Find matching extd
      for(extd=ext->Next; extd; extd=extd->Next)
	{
	if (!strncmp(extd->Field,"extd.",5) && // extd
	    !strcmp(extd->Field+4,ext->Field+3) && // same label
	    !SealSearch(Processed,extd->Field)) // not processed
	  {
	  break;
	  }
	} // search for extd
      } // if ext.
    else if (!strncmp(vf->Field,"extd.",5) && !SealSearch(Processed,vf->Field)) // found ext!
      {
      extd = vf;
      // Find matching extd
      for(ext=extd->Next; ext; ext=ext->Next)
	{
	if (!strncmp(ext->Field,"ext.",4) && // extd
	    !strcmp(extd->Field+4,ext->Field+3) && // same label
	    !SealSearch(Processed,ext->Field)) // not processed
	  {
	  break;
	  }
	} // search for ext
      } // if extd.
    else { continue; } // nothing found

    // Mark them as processed
    if (ext)  { Processed = SealSetText(Processed,ext->Field,"1"); }
    if (extd) { Processed = SealSetText(Processed,extd->Field,"1"); }

    if (First)
      {
      First=false;
      if (!IsValid)
	{
	printf("  Warning: SEAL signature is invalid. External files are unverifiable.\n");
	}
      }

    // If it found a file, check if the file is a valid name
    if (ext)
      {
      if (!_FileLegal((const char*)ext->Value) || // not legal path
	  (ext->Value[0]=='/') || // no absolute paths
	  !strncmp((const char*)ext->Value,"../",3) || // no upward paths
	  strstr((const char*)ext->Value,"/../") ) // no upward paths
        {
	printf("  External File Error: Invalid filename: ");
	TaintPrint((const char *)ext->Value);
	printf("\n");
	NotValidated++;
	continue;
	}

      if (!SealIsFile((const char*)ext->Value,false)) // Does it exist?
        {
	printf("  External File Missing: ");
	TaintPrint((const char *)ext->Value);
	printf("\n");
	NotValidated++;
	continue;
	}

      if (!SealIsReadable((const char*)ext->Value,false)) // Can it be accessed?
        {
	printf("  External File Inaccessible: ");
	TaintPrint((const char *)ext->Value);
	printf("\n");
	NotValidated++;
	continue;
	}

      if (!extd || !exta) // nothing to check against?
	{
	printf("  External File Present (not validated): ");
	TaintPrint((const char *)ext->Value);
	printf("\n");
	NotValidated++;
	continue;
	}

      // I have ext and extd? Compare them!
      Processed = SealDigestFile(Processed,(const char*)ext->Value,"exta","extdcmp",NULL);
      extdcmp = SealSearch(Processed,"extdcmp");
      if (!extdcmp)
	{
	printf("  External File Inaccessible: "); // couldn't generate hash
	TaintPrint((const char *)ext->Value);
	printf("\n");
	NotValidated++;
	continue;
	}

#if 0
      DEBUGPRINT("exta = '%s'",exta);
      DEBUGPRINT("extd[%d] = '%s'",(int)extd->ValueLen,extd->Value);
      DEBUGPRINT("extc[%d] = '%s'",(int)extdcmp->ValueLen,extdcmp->Value);
#endif
      if ((extd->ValueLen != extdcmp->ValueLen) ||
	  memcmp(extd->Value, extdcmp->Value, extdcmp->ValueLen))
	{
	printf("  External File Mismatch: "); // failed to validate!
	TaintPrint((const char *)ext->Value);
	printf("\n");
	NotValidated++;
	continue;
	}

      // OMG! IT VALIDATED!
      printf("  External File Matched (validated): ");
      TaintPrint((const char *)ext->Value);
      printf("\n");
      } // if ext exists

    else if (extd) // extd without ext?
      {
      UnknownCount++;
      NotValidated++;
      }
    } // Foreach Args

  if (UnknownCount > 0)
    {
    printf("  External File Unknown: %d external digest%s without filename%s\n",
	UnknownCount,
	(UnknownCount==1) ? "" : "s",
	(UnknownCount==1) ? "" : "s");
    }

  SealDel(Processed,NULL); // delete temp list
  return(NotValidated);
} /* SealExtVerify() */

