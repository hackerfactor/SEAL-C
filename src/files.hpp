/************************************************
 SEAL: implemented in C
 See LICENSE

 General file and I/O handling.
 ************************************************/
#ifndef FILES_HPP
#define FILES_HPP

// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "seal.hpp"

typedef struct stat64 stat_t;

typedef struct
  {
  FILE *fp;
  byte *mem;
  uint64_t memsize;
  } mmapfile;

unsigned char *	GetPassword	();

char *	MakeFilename	(char *Template, const char *Filename);
bool	CopyFile	(const char *dst, const char *src);

FILE *	SealFileOpen	(const char *fname, const char *mode);
#define SealFileClose(x)	fclose(x)
void	SealFileWrite	(FILE *Fout, size_t Len, byte *Data);

#ifndef PROT_NONE
#define PROT_NONE       0
#define PROT_READ       1
#define PROT_WRITE      2
#endif
mmapfile *	MmapFile	(const char *Filename, int Prot);
void	MmapFree	(mmapfile *Mmap);

#endif
