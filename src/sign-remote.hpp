/************************************************
 SEAL: implemented in C
 See LICENSE

 Handling remote signing.
 ************************************************/
#ifndef SIGN_REMOTE_HPP
#define SIGN_REMOTE_HPP

// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "seal.hpp"

bool	SealIsURL	(sealfield *Args);
sealfield *	SealSignURL	(sealfield *Args);

#endif
