/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling DNS requests and caching.
 ************************************************/
#ifndef SEAL_DNS_HPP
#define SEAL_DNS_HPP

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "seal.hpp"

void	SealDNSLoadFile	(const char *Fname);
sealfield *	SealDNSGet	(sealfield *Args, int DNSRecordNumber);
int	SealDNSCount	(sealfield *Args);
void	SealDNSWalk	(); // debugging
void	SealDNSFlushCache	();

#endif
