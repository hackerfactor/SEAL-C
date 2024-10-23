/************************************************
 SEAL: implemented in C
 See LICENSE

 General file and I/O handling.
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <limits.h> // UINT_MAX
#include <getopt.h> // getopt()
#include <sys/types.h> // stat()
#include <sys/stat.h> // stat()
#include <libgen.h> // dirname(), basename()
#include <termios.h> // for reading password
#include <fcntl.h>
#ifndef __WIN32__
  #include <sys/mman.h> /* for mmap() */
#endif

#include "seal.hpp"
#include "files.hpp"

/**************************************
 GetPassword(): allocate and populate the password string.
 Maximum password length is 255 characters.
 NOTE: This will accept a 1-letter password!
 Returns: null-terminated allocated string or NULL if no password.
 Caller must free() string.
 **************************************/
unsigned char *	GetPassword	()
{
  FILE *fp;
  unsigned char *Pwd;
  int c,len;
  static struct termios oldt, newt;

  fp = fopen("/dev/tty", "r+F");
  if (!fp) { return(NULL); } // No tty? No problem! No password!
  setvbuf(fp, NULL, _IONBF, 0); // no buffering

  // disable echo!
  tcgetattr(fileno(fp), &oldt);
  newt = oldt;
  newt.c_lflag &= ~(ECHO);
  tcsetattr(fileno(fp), TCSANOW, &newt);

  fprintf(stderr,"Enter password (blank for no password): ");
  fflush(stderr);
  Pwd = (unsigned char*)calloc(256+4,1);
  len=0;
  for(c=fgetc(fp); (c != '\n') && (c >= 0) && (len < 255); c=fgetc(fp))
    {
    if ((c==0x08) || (c==0x7f)) // backspace or delete
	{
	if (len > 0)
	  {
	  len--;
	  Pwd[len]=0;
	  }
	}
    else // save character
	{
	Pwd[len] = c;
	len++;
	}
    }
  fprintf(stderr,"\n");

  // reset echo (because tty may be tied to stdin)
  tcsetattr(fileno(fp), TCSANOW, &oldt);

  fclose(fp);

  if (len==0)
    {
    free(Pwd);
    return(NULL);
    }
  return(Pwd);
} /* GetPassword() */

/**************************************
 MakeFilename(): allocate and populate the output string.
 Returns: allocated string with filename.
 Caller must free() string.
 **************************************/
char *	MakeFilename	(char *Template, const char *Filename)
{
  char *Fname, *p;
  int Len2,Len;

  // Divide up Filename into directory, basename, and extension
  char *dcopy, *bcopy, *ecopy; // via malloc
  char *dname, *bname, *ename; // DO NOT FREE

  dcopy = strdup(Filename);
  bcopy = strdup(Filename);
  dname = dirname(dcopy);
  bname = basename(bcopy);
  p = strrchr(bname,'.'); // is there an extension?
  if (p)
    {
    Len = strlen(p);
    ecopy = (char*)calloc(Len+2,1);
    memcpy(ecopy, p, Len);
    p[0]='\0'; // Remove extension from bname
    }
  else
    {
    ecopy = (char*)calloc(5,1);
    }
  ename = ecopy;

  /*****
   Now for the hard part:
   Add in the templace, but replace every known '%' code.
   *****/
  Fname=NULL;
  Len=0;
  for(p=strchr(Template,'%'); p; p=strchr(Template,'%'))
    {
    // Copy over the text before '%'
    Len2 = strlen(Template) - strlen(p);
    Fname = (char*)realloc(Fname,Len+Len2+4);
    memcpy(Fname+Len,Template,Len2);

    // Move pointer to the '%'
    Len += Len2;
    Template += Len2;

    switch(p[1])
      {
      case 'b': // Copy basename
	Len2 = strlen(bname);
	Fname = (char*)realloc(Fname,Len+Len2+4);
	memcpy(Fname+Len,bname,Len2);
	memset(Fname+Len+Len2,0,4);
	Len += Len2;
	break;

      case 'd': // Copy dirname
	Len2 = strlen(dname);
	Fname = (char*)realloc(Fname,Len+Len2+4);
	memcpy(Fname+Len,dname,Len2);
	memset(Fname+Len+Len2,0,4);
	Len += Len2;
	break;

      case 'e': // Copy extension
	Len2 = strlen(ename);
	Fname = (char*)realloc(Fname,Len+Len2+4);
	memcpy(Fname+Len,ename,Len2);
	memset(Fname+Len+Len2,0,4);
	Len += Len2;
	break;

      case '%': // Copy '%'
	Fname[Len]='%'; // I already allocated an extra space
	Len++;
	break;

      default:
	fprintf(stderr,"ERROR: Output filename contains illegal character: %%");
	if (isprint(p[1]) && !isspace(p[1])) { fprintf(stderr,"%c",p[1]); }
	fprintf(stderr,"\n");
	exit(1);
      }
    Template+=2; // move past '%'
    }

  // Copy any text after last '%'
  if (Template[0])
	{
	Len2 = strlen(Template);
	Fname = (char*)realloc(Fname,Len+Len2+4);
	memcpy(Fname+Len,Template,Len2);
	memset(Fname+Len+Len2,0,4);
	}

  free(ecopy);
  free(bcopy);
  free(dcopy);
  return(Fname);
} /* MakeFilename() */

/**************************************
 SealFileOpen(): Open a file for reading, writing, appending.
 Same as fopen, but with common abort.
 Caller needs to call SealFileClose().
 **************************************/
FILE *	SealFileOpen   (const char *fname, const char *mode)
{
  FILE *Fout;
  Fout = fopen(fname,mode);
  if (!Fout)
	{
	fprintf(stderr,"ERROR: Unable to access '%s'. Aborting.\n",fname);
	exit(1);
	}
  return(Fout);
} /* SealFileOpen() */

/**************************************
 SealFileWrite(): Write data to a file.
 Abort on failure.
 **************************************/
void	SealFileWrite   (FILE *Fout, size_t Len, byte *Data)
{
  size_t Wrote,w;

  for(Wrote=0; Wrote < Len; Wrote += w)
    {
    w = fwrite(Data+Wrote, 1, Len-Wrote, Fout);
    if (w <= 0)
      {
      fprintf(stderr,"ERROR: Failed to write to file. Aborting.\n");
      exit(1);
      }
    }
} /* SealFileWrite() */

/**************************************
 MmapFile(): memory map the file for quick access.
 Used for rapidly computing checksums, scanning, and
 changing values.
 Returns: mmapfile* or NULL.
 **************************************/
mmapfile *	MmapFile	(const char *Filename, int Prot)
{
  mmapfile *Mmap;
  int FileHandle;

  // allocate structure
  Mmap = (mmapfile*)calloc(sizeof(mmapfile),1);
  if (!Mmap) // should never happen
    {
    fprintf(stderr,"ERROR: Cannot allocate mmap structure\n");
    exit(1);
    }

  // Open file and check it
  if (Prot & PROT_WRITE)
    {
    Mmap->fp = fopen(Filename,"rb+");
    }
  else
    {
    Mmap->fp = fopen(Filename,"rb");
    }
  if (!Mmap->fp)
    {
    fprintf(stderr,"ERROR: Cannot open file (%s)\n",Filename);
    free(Mmap);
    exit(1);
    }

  // mmap requires file handle
  FileHandle = fileno(Mmap->fp);
  if (FileHandle == -1) // should never happen since fopen worked
    {
    fprintf(stderr,"ERROR: File inaccessible (%s)\n",Filename);
    fclose(Mmap->fp);
    free(Mmap);
    exit(1);
    }

  stat_t Stat;
  if ((fstat64(FileHandle,&Stat) == -1) || !S_ISREG(Stat.st_mode))
    {
    fprintf(stderr,"ERROR: Not a regular file (%s)\n",Filename);
    fclose(Mmap->fp);
    free(Mmap);
    exit(1);
    }

  Mmap->memsize = Stat.st_size;
  Mmap->mem = (byte *)mmap64(0,Mmap->memsize,Prot,MAP_SHARED,FileHandle,0);
  if (!Mmap->mem || (Mmap->mem == MAP_FAILED)) // should never happen
    {
    fprintf(stderr,"ERROR: Memory map failed for file (%s)\n",Filename);
    fclose(Mmap->fp);
    free(Mmap);
    exit(1);
    }

  return(Mmap);
} /* MmapFile() */

/**************************************
 MmapFree(): Free memory map from MmapFile.
 **************************************/
void	MmapFree	(mmapfile *Mmap)
{
  if (!Mmap) { return; }
  munmap(Mmap->mem,Mmap->memsize);
  fclose(Mmap->fp);
  free(Mmap);
} /* MmapFree() */

/**************************************
 CopyFile(): Copy from src to dst.
 This is used during signing to create the output file.
 Returns: true on success, exits on failure.
 **************************************/
bool	CopyFile	(const char *dst, const char *src)
{
  mmapfile *Mmap;
  FILE *Fout;
  uint64_t TotalOut;
  size_t WriteOut;

  Mmap = MmapFile(src,PROT_READ);
  if (!Mmap) // never happens since MmapFile checks errors
    {
    fprintf(stderr,"ERROR: Copy failed from file (%s)\n",src);
    exit(1);
    }

  Fout = fopen(dst,"wb+");
  if (!Fout)
    {
    fprintf(stderr,"ERROR: Copy failed to file (%s)\n",dst);
    exit(1);
    }

  WriteOut = TotalOut = 0;
  while(TotalOut < Mmap->memsize)
	{
	WriteOut = Min(Mmap->memsize-TotalOut,UINT_MAX);
	WriteOut = fwrite(Mmap->mem+TotalOut, 1, WriteOut, Fout);
	if (WriteOut <= 0) // write failure
	  {
	  fprintf(stderr,"ERROR: Copy from (%s) to (%s) failed\n",src,dst);
	  exit(1);
	  }
	TotalOut += WriteOut;
	}

  if (TotalOut < WriteOut) // if copy failed
        {
	fclose(Fout);
	unlink(dst);
	exit(1); // abort
	}

  // Clean up
  fclose(Fout);
  MmapFree(Mmap);
  return(true);
} /* CopyFile() */

