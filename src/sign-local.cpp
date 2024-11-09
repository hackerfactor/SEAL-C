/************************************************
 SEAL: implemented in C
 See LICENSE

 Handling certs: generation, signing, and verifying.

 NOTE: Most of this code is in C, not C++.
 Why C?  I like think it's a simpler language.
 I find C++ is often too unreadable where there are too many nested classes
 or "<<" output operators.  And overloading operators can negatively impact
 readability, especially when the overloading is not intuitive.

 Basically, I've seen way too much C++ where it was readable by the
 original developer and not by anyone else.

 Coming from a security and QA background:
 The simpler the code, the less likely it is to have hidden errors.
 C is as simple as it gets without switching to a weak-typing language.

 ===================
 Algorithms:
   DSA: deprecated and discouraged. Do not use. Not supported.
   RSA: widely used
   EC: Lots of types
     NIST Standard default: P-256 aka prime256v1 aka secp256r1
   ED25519: Adopted by NIST in 2019 as part of FIPS 186-5.
     OpenSSL doesn't (yet) support it with EVP_PKEY_sign_init
     https://github.com/openssl/openssl/issues/5873#issuecomment-378917092
     ed25519 cannot be used with a separate digest.
     Solution: https://github.com/openssl/openssl/pull/23240/files
     Openssl 3.3.2 does not work.
     Openssl 3.3.4 MAY not work. (waiting for official release)
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h> // for isdigit()
#include <time.h> // for timestamp
#include <sys/time.h> // for timestamp
#include <math.h> // for pow
#include <fcntl.h>  // for access()

#include "seal.hpp"
#include "files.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"

// For openssl 3.x
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/buffer.h> // for BUF_MEM
#include <openssl/evp.h>
#include <openssl/rsa.h> // rsa algorithm
#include <openssl/ec.h> // elliptic curve algorithms
#include <openssl/x509.h>

// Include ed25519? (Disabled; doesn't work yet.)
#define INC_ED25519 0

EVP_PKEY *PrivateKey=NULL;

/********************************************************
 SealFreePrivateKey(): release the private key.
 ********************************************************/
void	SealFreePrivateKey	()
{
  if (PrivateKey) { EVP_PKEY_free(PrivateKey); }
  PrivateKey=NULL;
} /* SealFreePrivateKey() */

/********************************************************
 SealIsLocal(): Is the signer local (false) or remote (true)?
 ********************************************************/
bool    SealIsLocal       (sealfield *Args)
{
  char *Str;
  if (!Args) { return(false); } // must be defined
  Str = SealGetText(Args,"keyfile"); // must be defined
  if (!Str) { return(false); }
  if (access(Str, R_OK) != 0) { return(false); }
  return(true);
} /* SealIsLocal() */

/**************************************
 SealLoadPrivateKey(): Load the private key for signing.
 Depends on OpenSSL 3.x.
 Returns: keypair or exits
 Stores keypair in global!
 Caller must call SealFreePrivateKey()!
 **************************************/
EVP_PKEY *	SealLoadPrivateKey	(sealfield *Args)
{
  FILE *fp;
  OSSL_DECODER_CTX *decoder=NULL;
  char *keyfile, *keyalg;

  // Only load it once
  if (PrivateKey) { SealFreePrivateKey(); }

  keyfile = SealGetText(Args,"keyfile");
  if (!keyfile)
    {
    fprintf(stderr," ERROR: No keyfile defined.\n");
    exit(1);
    }

  keyalg = SealGetText(Args,"ka");
  if (keyalg && !strcmp(keyalg,"rsa"))
    {
    decoder = OSSL_DECODER_CTX_new_for_pkey(&PrivateKey, "PEM", NULL, "RSA", EVP_PKEY_KEYPAIR, NULL, NULL);
    }
#if INC_ED25519
  else if (keyalg && !strcmp(keyalg,"ed25519"))
    {
    decoder = OSSL_DECODER_CTX_new_for_pkey(&PrivateKey, "PEM", NULL, "ED25519", EVP_PKEY_KEYPAIR, NULL, NULL);
    }
#endif
  // If more algorithms are supported, this needs to be updated.
  else if (keyalg) // && !strcmp(keyalg,"ec"))
    {
    // everything else currently supported is ec.
    decoder = OSSL_DECODER_CTX_new_for_pkey(&PrivateKey, "PEM", NULL, "EC", EVP_PKEY_KEYPAIR, NULL, NULL);
    }
  else
    {
    fprintf(stderr," ERROR: No key algorithm defined.\n");
    exit(1);
    }
  if (decoder == NULL)
    {
    fprintf(stderr," ERROR: Unable to open context for private key.\n");
    exit(1);
    }

  // Open private key file
  fp = fopen(keyfile,"rb");
  if (!fp)
    {
    fprintf(stderr," ERROR: Unable to open private key file (%s).\n",keyfile);
    exit(1);
    }

  // Decode from file!
  // First assume no password.
  // If it works, then no password was needed.
  // If it fails, then try a password!
  int rc;
  rewind(fp);
  rc = OSSL_DECODER_from_fp(decoder, fp); // assume no password
  if (rc != 1) // failed; need password
    {
    unsigned char *pwd;
    bool FreePwd=false;
    // Try a password!
    pwd = (unsigned char*)SealGetText(Args,"@genpass");
    if (!pwd) { pwd = GetPassword(); FreePwd=true; }
    if (pwd && pwd[0])
      {
      // I don't need to set_cipher since the file specifies the cipher.
      // Set the password.
      if (OSSL_DECODER_CTX_set_passphrase(decoder,pwd,strlen((char*)pwd)) != 1)
	{
	fprintf(stderr," ERROR: Unable to set the password.\n");
	exit(1);
	}
      if (FreePwd) { free(pwd); }
      rewind(fp);
      rc = OSSL_DECODER_from_fp(decoder, fp); // decode with password
      }
    // else: No password already failed.
    }
  if (rc != 1)
    {
    fprintf(stderr," ERROR: Unable to load private key file (%s).\n",keyfile);
    exit(1);
    }

  // If it got here, then it worked.
  OSSL_DECODER_CTX_free(decoder);
  return(PrivateKey);
} /* SealLoadPrivateKey() */

/**************************************
 SealSignLocal(): Sign data using the private key!
 If there is no @digest1, then set the signature size (@sigsize).
 If there is @digest1, then set the signature (@signature).
 **************************************/
sealfield *	SealSignLocal	(sealfield *Args)
{
  EVP_PKEY_CTX *ctx;
  const EVP_MD* (*mdf)(void);
  char *digestalg=NULL;
  char *sf; // signing format (date, hex, whatever)
  char *keyalg; // rsa or ec
  char datestr[30], *s;
  int datestrlen=0;
  size_t siglen=0; // raw signature length
  size_t enclen=0; // encoded signature length
  int i;

  // Keys must be loaded.
  if (!PrivateKey) { SealLoadPrivateKey(Args); }

  // Set the date string
  memset(datestr,0,30);
  sf = SealGetText(Args,"sf"); // SEAL's 'sf' parameter; signing format (date, hex, whatever)
  if (!strncmp(sf,"date",4)) // if there's a date, compute it!
    {
    struct timeval tv;
    struct tm *tmp; // time pointer

    // How many fraction decimal places?
    int fract=0;
    s=sf+4;
    if (isdigit(s[0]))
      {
      fract=s[0]-'0';
      s++;
      }

    // Get and generate the date
    gettimeofday(&tv,NULL);
    tmp = gmtime(&tv.tv_sec);
    snprintf(datestr,30,"%04u%02u%02u%02u%02u%02u",
      (tmp->tm_year+1900) % 10000,
      (tmp->tm_mon+1) % 100,
      (tmp->tm_mday) % 100,
      (tmp->tm_hour) % 100,
      (tmp->tm_min) % 100,
      (tmp->tm_sec) % 100);
    if ((fract > 0) && (fract < 6))
      {
      snprintf(datestr+14,fract+2,".%0*d",
        fract, (int)(tv.tv_usec / powf(10,6-fract)));
      }
    else if (fract >= 6)
      {
      snprintf(datestr+14,fract+2,".%06ld",tv.tv_usec);
      // I only have 6 decimal points! Pad with zeros!
      for(i=7; i < fract; i++)
        {
	datestr[14+i]='0';
	}
      }
    datestrlen = strlen(datestr);
    Args = SealSetText(Args,"@sigdate",datestr);
    } // set datestr

  // Apply double digest (date:userid:) as needed
  // SealDoubleDigest uses @sigdate, so must be done AFTER date!
  Args = SealDoubleDigest(Args);

  // Set the digest algorithm
  digestalg = SealGetText(Args,"da"); // SEAL's 'da' parameter
  if (!strcmp(digestalg,"sha224")) { mdf = EVP_sha224; }
  else if (!strcmp(digestalg,"sha256")) { mdf = EVP_sha256; } // default
  else if (!strcmp(digestalg,"sha384")) { mdf = EVP_sha384; }
  else if (!strcmp(digestalg,"sha512")) { mdf = EVP_sha512; }
  else
    {
    fprintf(stderr," ERROR: Unsupported digest algorithm (da=%s).\n",digestalg);
    exit(1);
    }

  // Set the encryption algorithm
  keyalg = SealGetText(Args,"ka");
  if (!strcmp(keyalg,"rsa")) { ; }
#if INC_ED25519
  else if (!strcmp(keyalg,"ed25519")) { ; }
#endif
  else if (!strcmp(keyalg,"ec")) { ; }
  else
    {
    fprintf(stderr," ERROR: Unsupported key algorithm (ka=%s).\n",keyalg);
    exit(1);
    }

  // Allocated the context handle
  ctx = EVP_PKEY_CTX_new_from_pkey(NULL, PrivateKey, NULL);
  if (!ctx)
	{
	fprintf(stderr," ERROR: Unable to initialize the sign context.\n");
	exit(1);
	}

  // Initialize context handle
   if (EVP_PKEY_sign_init(ctx) <= 0) // everyone else
	{
	fprintf(stderr," ERROR: Initializing the sign context failed.\n");
	exit(1);
	}

  // RSA requires padding
  if (!strcmp(keyalg,"rsa"))
    {
    if ( (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) != 1) ||
	 (EVP_PKEY_CTX_set_signature_md(ctx, mdf()) != 1) )
	{
	fprintf(stderr," ERROR: Unable to initialize the RSA algorithm.\n");
	exit(1);
	}
    }

  // Find the key size
  siglen = EVP_PKEY_size(PrivateKey);
  //EVP_PKEY_sign(ctx, NULL, &siglen, NULL, 0); // get size; does not work with ed25519

  /*****
   Convert it to the output format.
   Binary signature is stored in sig!
   *****/
  enclen=0;
  if (strstr(sf,"base64"))
    {
    // base64 is a 4/3 expansion with padding to a multiple of 4
    enclen = ((siglen+2)/3) * 4;
    }
  else if (strstr(sf,"bin")) { enclen = siglen; } // bad choice
  else if (strstr(sf,"hex")) { enclen = siglen*2; }
  else if (strstr(sf,"HEX")) { enclen = siglen*2; }
  else
    {
    fprintf(stderr," ERROR: Unknown signature format (%s).\n",sf);
    exit(1);
    }
  if (datestrlen) { enclen += datestrlen+1; } // "date:"
  Args = SealSetU32index(Args,"@sigsize",0,enclen);

  /***** Signing! *****/
  if (SealSearch(Args,"@digest1")) // if digest exists, then do signing!
    {
    sealfield *DigestBin;
    sealfield *Sign;

    Args = SealAlloc(Args,"@signaturebin",siglen,'x');
    Sign = SealSearch(Args,"@signaturebin");
    DigestBin = SealSearch(Args,"@digest2");
    if (!DigestBin) { DigestBin = SealSearch(Args,"@digest1"); }
    if (EVP_PKEY_sign(ctx, Sign->Value, &siglen, DigestBin->Value, DigestBin->ValueLen) != 1)
      {
      fprintf(stderr," ERROR: Failed to sign.\n");
      exit(1);
      }

    // Check for padding
    Sign->ValueLen = siglen; // size may be smaller

    // Encode the signature
    Args = SealCopy(Args,"@enc","@signaturebin");
    if (strstr(sf,"base64")) { SealBase64Encode(SealSearch(Args,"@enc")); }
    else if (strstr(sf,"hex")) { SealHexEncode(SealSearch(Args,"@enc"),false); }
    else if (strstr(sf,"HEX")) { SealHexEncode(SealSearch(Args,"@enc"),true); }
    // else if (strstr(sf,"bin")) { ; } /* Already handled */

    // Set the date as needed
    if (datestrlen)
      {
      sealfield *enc;
      enc = SealSearch(Args,"@enc");
      Args = SealSetText(Args,"@signatureenc",datestr);
      Args = SealAddC(Args,"@signatureenc",':');
      Args = SealAddBin(Args,"@signatureenc",enc->ValueLen,enc->Value);
      Args = SealDel(Args,"@enc");
      }
    else
      {
      Args = SealMove(Args,"@signatureenc","@enc");
      }

    // Add padding as needed
    size_t i;
    siglen = SealGetU32index(Args,"@sigsize",0);
    Sign = SealSearch(Args,"@signatureenc");
    for(i=Sign->ValueLen; i < siglen; i++)
      {
      Args = SealAddC(Args,"@signatureenc",' ');
      }
    }

  // Clean up
  EVP_PKEY_CTX_free(ctx);
  return(Args);
} /* SealSignLocal() */

/**************************************
 PrintDNSstring(): Print a string for DNS.
 This includes smart quoting.
 **************************************/
void	PrintDNSstring	(FILE *fp, const char *Label, sealfield *vf)
{
  // Don't worry about lengths since Label and Value are null-terminated.
  if (strchr((char*)vf->Value,'"') ||
      strchr((char*)vf->Value,'\'') ||
      strchr((char*)vf->Value,' '))
	{
	fprintf(stderr," ERROR: Invalid parameter: '%.*s' value cannot contain quotes or spaces.\n",
	  (int)vf->FieldLen, vf->Field);
	exit(1);
	}

  fprintf(fp," %s=%s",Label,vf->Value);
} /* PrintDNSstring() */

/**************************************
 SealGenerateKeys(): Create the public and private keys!
 Depends on OpenSSL 3.x.
 **************************************/
void	SealGenerateKeys	(sealfield *Args)
{
  // Get the algorithm and bits.
  FILE *fp;
  sealfield *vf;
  EVP_PKEY_CTX *pctx=NULL;
  EVP_PKEY *keypair = NULL;
  OSSL_ENCODER_CTX *encoder=NULL;
  unsigned int Bits;
  char *keyfile=NULL, *pubfile=NULL;

  vf = SealSearch(Args,"keybits");
  if (!vf) { Bits=2048; }
  else { Bits = atoi((char*)(vf->Value)); }
  // Bits size is already validated

  vf = SealSearch(Args,"dnsfile");
  if (!vf || !vf->ValueLen)
    {
    fprintf(stderr," ERROR: dnsfile (-D) must be set.\n");
    exit(1);
    }
  pubfile = (char*)vf->Value;

  vf = SealSearch(Args,"keyfile");
  if (!vf || !vf->ValueLen)
    {
    fprintf(stderr," ERROR: keyfile (-k) must be set.\n");
    exit(1);
    }
  keyfile = (char*)vf->Value;

  // If support for other algorithms is added, do it here.
  // For now, only supporing RSA.
  // Generate the key

  vf = SealSearch(Args,"ka");
  if (!vf) { keypair=NULL; }
  else if (!strcmp((char*)(vf->Value),"rsa"))
    {
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx ||
	(EVP_PKEY_keygen_init(pctx) != 1) ||
	(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx,Bits) != 1) ||
	(EVP_PKEY_keygen(pctx, &keypair) != 1))
	{ keypair=NULL; }
    if (pctx) { EVP_PKEY_CTX_free(pctx); }
    }
#if INC_ED25519
  else if (!strcmp((char*)(vf->Value),"ed25519")) 
    {
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx ||
	(EVP_PKEY_keygen_init(pctx) != 1) ||
	(EVP_PKEY_keygen(pctx, &keypair) != 1) ||
	(EVP_PKEY_CTX_free(pctx) != 1))
	{ keypair=NULL; }
    if (pctx) { EVP_PKEY_CTX_free(pctx); }
    }
#endif
  else if (!strcmp((char*)(vf->Value),"ec")) 
    {
    // "ec" is a generic class. When generating, assume P-256 for now.
    keypair = EVP_EC_gen("P-256");
    Args = SealSetText(Args,"ka","ec");
    }
  else // some kind of specific elliptic curve
    {
    keypair = EVP_EC_gen((char*)(vf->Value));
    Args = SealSetText(Args,"ka","ec");
    }

  if (!keypair)
    {
    fprintf(stderr," ERROR: Unable to generate the keys.\n");
    exit(1);
    }

  // Save the private key as PEM
  encoder = OSSL_ENCODER_CTX_new_for_pkey(keypair, EVP_PKEY_KEYPAIR, "PEM", NULL, NULL);
  if (!encoder)
    {
    fprintf(stderr," ERROR: Unable to generate the private key.\n");
    exit(1);
    }

  // Set (optional) password
  {
  unsigned char *pwd;
  bool FreePwd=false;

  pwd = (unsigned char*)SealGetText(Args,"@genpass");
  if (!pwd) { pwd = GetPassword(); FreePwd=true; }
  if (pwd && pwd[0])
    {
    /*****
     Add the password to the private key.
     AES-128-CBC is good enough for protecting the private key file.
     *****/
    if (OSSL_ENCODER_CTX_set_cipher(encoder, "AES-128-CBC", NULL) != 1)
	{
	fprintf(stderr," ERROR: Unable to set password cipher.\n");
	exit(1);
	}
    if (OSSL_ENCODER_CTX_set_passphrase(encoder,pwd,strlen((char*)pwd)) != 1)
	{
	fprintf(stderr," ERROR: Unable to set the password.\n");
	exit(1);
	}
    }
  if (pwd && FreePwd) { free(pwd); }
  }

  fp = fopen(keyfile,"wb");
  if (!fp)
    {
    fprintf(stderr," ERROR: Unable to write to the private key file (%s).\n",keyfile);
    exit(1);
    }

  if (!OSSL_ENCODER_to_fp(encoder,fp))
    {
    fprintf(stderr," ERROR: Unable to save to the private key file (%s).\n",keyfile);
    exit(1);
    }

  fclose(fp);
  OSSL_ENCODER_CTX_free(encoder);

  // Save public key as DER!
  encoder = OSSL_ENCODER_CTX_new_for_pkey(keypair,
	EVP_PKEY_PUBLIC_KEY,
	//OSSL_KEYMGMT_SELECT_ALL_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
	//EVP_PKEY_KEY_PARAMETERS | EVP_PKEY_PUBLIC_KEY,
	"DER", NULL, NULL);
  if (!encoder)
    {
    fprintf(stderr," ERROR: Unable to generate the public key.\n");
    // don't delete the private keyfile since it can still generate public keys
    exit(1);
    }

  // Save binary public key to memory (I'll base64-encode it without the headers)
  {
  BIO *bio = BIO_new(BIO_s_mem());
  i2d_PUBKEY_bio(bio, keypair);
  size_t derlen;
  unsigned char *derdata;
  derlen = BIO_get_mem_data(bio, &derdata);
  Args = SealSetBin(Args,"@pubder",derlen,derdata);
  SealBase64Encode(SealSearch(Args,"@pubder"));
  BIO_free(bio);
  }

  // Create DNS entry!
  fp = fopen(pubfile,"wb");
  if (!fp)
    {
    fprintf(stderr," ERROR: Unable to write to the public key file (%s).\n",pubfile);
    exit(1);
    }
  vf = SealSearch(Args,"seal");
  fprintf(fp,"seal=%.*s",(int)vf->ValueLen,vf->Value);
  vf = SealSearch(Args,"ka");
  PrintDNSstring(fp,"ka",vf);

  // Store vf if it isn't the default value
  vf = SealSearch(Args,"kv");
  if (vf && strcmp((char*)vf->Value,"1")) { PrintDNSstring(fp,"kv",vf); }

  // Store uid if it exists
  vf = SealSearch(Args,"uid");
  if (vf) { PrintDNSstring(fp,"uid",vf); }
  fprintf(fp," p=%s",SealGetText(Args,"@pubder")); // value is base64 public key!
  Args = SealDel(Args,"@pubder");

  // No comments in DNS; limited space!
  fprintf(fp,"\n");
  fclose(fp);

  printf("Private key written to: %s\n",keyfile);
  printf("Public DNS TXT value written to: %s\n",pubfile);
  EVP_PKEY_free(keypair);
} /* SealGenerateKeys() */

