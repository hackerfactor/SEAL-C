/************************************************
 SEAL: implemented in C
 See LICENSE

 Code for validating a SEAL record.
 ************************************************/
#ifndef SIGN_VERIFY_HPP
#define SIGN_VERIFY_HPP

// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "seal.hpp"
#include "files.hpp"

sealfield *	SealGetDNS	(sealfield *Rec);
sealfield *	SealRotateRecords	(sealfield *Rec);
sealfield *	SealVerify	(sealfield *Rec, mmapfile *Mmap);
sealfield *	SealVerifyFinal	(sealfield *Rec);

#endif
