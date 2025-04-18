/************************************************
 SEAL: implemented in C
 See LICENSE

 Main program.

 Return codes:
   0x00 No issues.
   0x01 At least one signature is invalid.
   0x02 At least one file without a signature.
   0x03 Both 0x01 and 0x02
   0x80 Error
 ************************************************/
// C headers
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h> // UINT_MAX
#include <ctype.h> // isalnum
#include <string.h> // memset
#include <getopt.h> // getopt()
#include <sys/types.h> // stat()
#include <sys/stat.h> // stat()
#include <libgen.h> // dirname(), basename()
#include <termios.h> // for reading password
#include <fcntl.h>
#ifndef __WIN32__
  #include <sys/mman.h> /* for mmap() */
#endif

// For openssl usage
#include <openssl/evp.h>

#include "seal.hpp"
#include "files.hpp"
#include "formats.hpp"
#include "seal-parse.hpp"
#include "sign.hpp"

/**************************************
 ReadCfg(): Read the config file.
 A config file can overwrite any already-known parameters.
 **************************************/
sealfield *	ReadCfg	(sealfield *Args)
{
  char *fname;
  FILE *fp;
  int c,b;
  int fieldlen,valuestart,valueend;
  /*****
   Finite state machine states
   0=read field
   1=read padding to =
   2=read padding after =
   3=read value
   4=ignore line (comment)
   *****/
  int LineNo,state;
  char Buf[1024]; // no more than 1K per line

  fname = SealGetText(Args,"config");
  if (!fname) { return(Args); }
  if (access(fname, F_OK) != 0) // if file does not exist
    {
    return(Args);
    }

  fp=fopen(fname,"r");
  if (!fp)
    {
    fprintf(stderr,"ERROR: Unable to read configuration file: '%s'\n",fname);
    exit(0x80);
    }

  /* Read the file */
  b=0;
  memset(Buf,0,1024);
  state = fieldlen = valuestart = valueend = 0;
  LineNo=1;
  while((c=fgetc(fp)) >= 0)
    {
    if (b > 1024)
	{
	fprintf(stderr,"ERROR: configuration file line too long: line %d in '%s'\n",LineNo,fname);
	exit(0x80);
	}

    if (c=='\n') // end of line!
	{
	// check for valid line
	if (state==4) { ; } // comment
	else if ((state==0) && (b==0)) { ; } // blank line
	else if (state==3) // good field/value
	  {
	  Buf[fieldlen]='\0'; // null-terminate field name
	  if (SealGetText(Args,Buf)==NULL)
	    {
	    fprintf(stderr,"ERROR: unknown field '%.*s': line %d in '%s'\n",fieldlen,Buf,LineNo,fname);
	    exit(0x80);
	    }
	  //fprintf(stderr,"DEBUG: Line[%d] field='%.*s' value='%.*s'\n",LineNo,fieldlen,Buf,valueend-valuestart,Buf+valuestart);
	  Args=SealSetText(Args,Buf,Buf+valuestart);
	  }
	else // unknown line format
	  {
	  fprintf(stderr,"ERROR: configuration file bad format: line %d in '%s'\n",LineNo,fname);
	  exit(0x80);
	  }

	// Reset for next line
	LineNo++;
	b=0;
	memset(Buf,0,1024);
	state = fieldlen = valuestart = valueend = 0;
	state=0;
	}

    if (state==4) { ; } // ignore it

    if (state==0) // reading field name
	{
	if ((b==0) && (c=='#')) { state=4; continue; } // comment
	if ((b==0) && isspace(c)) { continue; } // skip initial spaces
	if ((b==0) && !isalnum(c)) // bad start
	  {
	  fprintf(stderr,"ERROR: configuration file bad initial character: line %d in '%s'\n",LineNo,fname);
	  exit(0x80);
	  }
	if (isalnum(c))
	  {
	  Buf[b]=c; b++;
	  fieldlen++;
	  }
	else if (isspace(c))
	  {
	  Buf[b]=c; b++;
	  state=1;
	  continue;
	  }
	else if (c=='=')
	  {
	  Buf[b]=c; b++;
	  state=2;
	  continue;
	  }
	}

    if (state==1) // reading space before "="
	{
	if (isspace(c)) { ; } // skip it
	else if (c=='=') // Got separator!
	  {
	  Buf[b]=c; b++;
	  state=2;
	  continue;
	  }
	}

    if (state==2) // reading space after "="
	{
	if (isspace(c)) { ; } // skip it
	else // Got start of value!
	  {
	  valuestart=b;
	  state=3; // fall through to reading value
	  }
	}

    if (state==3) // reading value
	{
	Buf[b]=c; b++;
	if (!isspace(c)) { valueend=b; }
	}
    }

  fclose(fp);
  return(Args);
} /* ReadCfg() */

/**************************************
 _mkdir(): Recursive mkdir.
 Directory path MUST be writable!
 **************************************/
void	_mkdir	(char *Path)
{
  char *p;
  struct stat st;

  p = strchr(Path,'/');
  if (Path[0]=='/') // skip initial slash
    {
    p = strchr(p+1,'/');
    }

  while(p)
    {
    p[0]='\0'; // terminate path string
    // Does it exist?
    if (stat(Path, &st) == 0)
      {
      // Already exists as a directory? Good!
      if (S_ISDIR(st.st_mode)) { ; }
      else // Already exists as something else? (Nope!)
        {
	fprintf(stderr,"ERROR: '%s' is not a directory. Aborting.\n",Path);
	exit(0x80);
	}
      }
    else // Create the path
      {
      if (mkdir(Path,0770) != 0)
        {
	fprintf(stderr,"ERROR: Cannot create directory '%s'. Aborting.\n",Path);
	exit(0x80);
	}
      }

    // Check next path segment
    p[0]='/'; // replace path string
    p = strchr(p+1,'/');
    }
} /* _mkdir() */

/**************************************
 WriteCfg(): Create the config file.
 NOTE: This exits!
 **************************************/
void	WriteCfg	(sealfield *Args)
{
  char *s;
  FILE *Fout;

  Fout = stdout;
  s = SealGetText(Args,"config");
  if (s && strcmp(s,"-")) // if config file and not stdout
    {
    // check if it already exists
    if (access(s,F_OK)==0)
      {
      char buf[5];
      memset(buf,0,5);
      fprintf(stderr,"WARNING: Configuration file already exists. Overwrite (y/n)?\n");
      if (!fgets(buf,5,stdin) || !strchr("Yy",buf[0]))
        {
	fprintf(stderr,"Aborting.\n");
	exit(0x80);
	}
      }
    else
      {
      _mkdir(s);
      }
    Fout = fopen(s,"wb");
    }

  fprintf(Fout,"# Common options\n");
  s=SealGetText(Args,"domain"); if (s && s[0]) { fprintf(Fout,"domain=%s\n",s); } else { fprintf(Fout,"#domain=\n"); }
  fprintf(Fout,"digestalg=%s\n",SealGetText(Args,"digestalg"));
  fprintf(Fout,"keyalg=%s\n",SealGetText(Args,"keyalg"));
  fprintf(Fout,"kv=%s\n",SealGetText(Args,"kv"));
  fprintf(Fout,"sf=%s\n",SealGetText(Args,"sf"));
  fprintf(Fout,"\n");

  fprintf(Fout,"# Informational options\n");
  s=SealGetText(Args,"info"); if (s && s[0]) { fprintf(Fout,"info=%s\n",s); } else { fprintf(Fout,"#info=\n"); }
  s=SealGetText(Args,"comment"); if (s && s[0]) { fprintf(Fout,"comment=%s\n",s); } else { fprintf(Fout,"#comment=\n"); }
  s=SealGetText(Args,"copyright"); if (s && s[0]) { fprintf(Fout,"copyright=%s\n",s); } else { fprintf(Fout,"#copyright=\n"); }
  fprintf(Fout,"\n");

  fprintf(Fout,"# Local signing options (for use with -s and -m)\n");
  s=SealGetText(Args,"keyfile"); if (s && s[0]) { fprintf(Fout,"keyfile=%s\n",s); } else { fprintf(Fout,"#keyfile=\n"); }
  fprintf(Fout,"\n");

  fprintf(Fout,"# Remote signing options (for use with -S and -M)\n");
  s=SealGetText(Args,"apiurl"); if (s && s[0]) { fprintf(Fout,"apiurl=%s\n",s); } else { fprintf(Fout,"#apiurl=\n"); }
  s=SealGetText(Args,"apikey"); if (s && s[0]) { fprintf(Fout,"apikey=%s\n",s); } else { fprintf(Fout,"#apikey=\n"); }
  s=SealGetText(Args,"id"); if (s && s[0]) { fprintf(Fout,"id=%s\n",s); } else { fprintf(Fout,"#id=\n"); }
  s=SealGetText(Args,"outfile"); if (s && s[0]) { fprintf(Fout,"outfile=%s\n",s); } else { fprintf(Fout,"#outfile=\n"); }
  fprintf(Fout,"\n");

  fprintf(Fout,"# Generating signature options (for use with -g)\n");
  s=SealGetText(Args,"dnsfile"); if (s && s[0]) { fprintf(Fout,"dnsfile=%s\n",s); } else { fprintf(Fout,"#dnsfile=\n"); }
  s=SealGetText(Args,"uuid"); if (s && s[0]) { fprintf(Fout,"uuid=%s\n",s); } else { fprintf(Fout,"#uuid=\n"); }
  fprintf(Fout,"\n");

  if (Fout != stdout)
    {
    fclose(Fout);
    fprintf(stderr,"Configuration file created: %s\n",SealGetText(Args,"config"));
    }
  exit(0);
} /* WriteCfg() */

/**************************************
 print_km_name(): Callback for OpenSSL listing key algorithms
 **************************************/
void	print_km_name	(const char *name, void *param)
{
  (void)(param); // avoid unused variable warnings
  if (name && !isdigit(name[0]) && !strstr(name,"-old") && !strchr(name,' '))
    {
    printf("        %s\n",name);
    }
} /* print_km_name() */

/**************************************
 print_km(): Callback for OpenSSL listing key algorithms
 **************************************/
void	print_km	(EVP_KEYMGMT *km, void *param)
{
  (void)(param); // avoid unused variable warnings
  EVP_KEYMGMT_names_do_all(km, print_km_name, NULL);
} /* print_km() */

/**************************************
 Usage(): Show usage and abort.
 **************************************/
void	Usage	(const char *progname)
{
  printf("Usage: %s [options] file [file...]\n",progname);
  printf("  -h, -?, --help    :: Show help; this usage\n");
  printf("  --config file.cfg :: Optional configuration file (default: $XDG_CONFIG_HOME/seal/config)\n");
  printf("  -v                :: Verbose debugging (probably not what you want)\n");
  printf("  -V, --version     :: Show the code version and exit.\n");
  printf("\n");
  printf("  Verifying:\n");
  printf("  Verify any SEAL signature in the file(s)\n");
  printf("  -D, --dnsfile fname  :: Optional: text file with DNS TXT value. (default: unset; use DNS)\n");
  printf("\n");
  printf("  Generate signature:\n");
  printf("  -g, --generate       :: Required: generate a signature\n");
  printf("  -D, --dnsfile fname  :: File for storing the public key for DNS (default: ./seal-public.dns)\n");
  printf("  -k, --keyfile fname  :: File for storing the private key in PEM format (default: ./seal-private.pem)\n");
  // NIST Approved: P-256 = prime256v1; default if you say "ec"
  // NIST Approved: P-384 = secp384r1
  printf("  -K, --keyalg alg     :: Key algorithm (rsa, ec, P-256; default: rsa)\n");
  // EVP_KEYMGMT_do_all_provided(NULL, print_km, NULL);
  printf("  --kv number          :: Unique key version (default: 1)\n");
  printf("  --uid text           :: Unique key identifier (default: not set)\n");
  printf("\n");
  printf("  Signing with a local private key:\n");
  printf("  -s, --sign           :: Required: Enable signing (requires lowercase 's')\n");
  printf("  -k, --keyfile fname  :: File for storing the private key in PEM format (default: ./seal-private.pem)\n");
  printf("\n");
  printf("  Signing with a remote signing service:\n");
  printf("  -S, --Sign           :: Required: Enable signing (requires uppercase 'S')\n");
  printf("  -u, --apiurl url     :: For remote signers (default: no url)\n");
  printf("  -a, --apikey id      :: For remote signers (default: no API key)\n");
  printf("  -i, --id id          :: User-specific identifier (default: no identifier)\n");
  printf("  --cacert file.crl    :: Use file.crl for trusted root certificates.");
  printf(" (default: ./cacert.crl)");
  printf("\n");
  printf("\n");
#ifdef __CYGWIN__
#else
  printf(" (default: unset; uses operating system defaults)");
#endif
  printf("\n");
  printf("  --cert-insecure      :: Do not validate server's TLS certificate.\n");
  printf("\n");
  printf("  Manual signing: (mostly for debugging; probably not what you want)\n");
  printf("  -M, --Manual ''      :: Generate the SEAL record with a stubbed value.\n");
  printf("  -M, --Manual digest  :: Given a hex digest, sign it using a remote service.\n");
  printf("  -m, --manual digest  :: Given a hex digest, sign it using a local key.\n");
  printf("\n");
  printf("  Common signing options (for local and remote)\n");
  printf("  -d, --domain domain  :: DNS entry with the public key (default: localhost.localdomain)\n");
  printf("  -o, --outfile fname  :: Output filename\n");
  printf("               Include '%%d' for directory name without final /\n");
  printf("               Include '%%b' for base filename\n");
  printf("               Include '%%e' for filename extension, including '.'\n");
  printf("               Include '%%%%' for a percent sign\n");
  printf("               Default: './%%b-seal%%e'\n");
  printf("  -O, --options  text  :: Signing-specific options (default: none)\n");
  printf("        -O text may contain a comma-separated list of options:\n");
  printf("        append  :: This is an appending signature; not final signature.\n");
  printf("        seAl,SEAL,teXt,tEXt,...  :: PNG: chunk name to use.\n");
  printf("  -K, --keyalg alg     :: Key algorithm  (default: rsa)\n");
  printf("  -A, --digestalg alg  :: Digest (hash) algorithm  (default: sha256)\n");
  printf("               Supports: sha224, sha256, sha384, sha512\n");
  printf("  --kv number          :: Unique key version (default: 1)\n");
  printf("  --sf text            :: Signing format (default: HEX)\n");
  printf("\n");
  printf("  Informational fields:\n");
  printf("  -C, --copyright text :: Copyright text (default: no added text)\n");
  printf("  -c, --comment text   :: Generic comment text (default: no added text)\n");
  printf("  --info text          :: Informational comment text (default: no added text)\n");
  printf("\n");
  printf("  External source reference:\n");
  printf("  --src url            :: URL to remote source (default: no url)\n");
  printf("  --srca sha256:base64 :: Encoding for source digest (default: sha256:base64 if srcd is used)\n");
  printf("  --srcd digest        :: Digest of remote source (default: no digest)\n");
  printf("\n");
  printf("  Return codes:\n");
  printf("    0x00 All files have valid signatures.\n");
  printf("    0x01 At least one signature is invalid.\n");
  printf("    0x02 At least one file without a signature.\n");
  printf("    0x03 Both 0x01 and 0x02\n");
  printf("    0x80 Error\n");
} /* Usage() */

/**************************************
 main()
 **************************************/
int main (int argc, char *argv[])
{
  sealfield *Args=NULL, *CleanArgs;
  int c;
  int Mode='v';
  int FileFormat='@';
  bool IsURL=false; // for signing, use URL?
  bool IsLocal=false; // for signing, use local?

  // Set default values
  Args = SealSetText(Args,"seal","1"); // SEAL version; currently always '1'
  Args = SealSetText(Args,"b","F~S,s~f"); // default byte range is everything
  Args = SealSetText(Args,"digestalg","sha256");
  Args = SealSetText(Args,"keyalg","rsa");
  Args = SealSetText(Args,"keybits","2048");
  Args = SealSetText(Args,"keyfile","./seal-private.pem");
  Args = SealSetText(Args,"outfile","./%b-seal%e");
  Args = SealSetText(Args,"options","");
  Args = SealSetText(Args,"kv","1");
  Args = SealSetText(Args,"sf","HEX");
  Args = SealSetText(Args,"domain","localhost.localdomain");
  Args = SealSetText(Args,"dnsfile","");
  Args = SealSetText(Args,"copyright","");
  Args = SealSetText(Args,"comment","");
  Args = SealSetText(Args,"info","");
  Args = SealSetText(Args,"id","");
  Args = SealSetText(Args,"apiurl","");
  Args = SealSetText(Args,"apikey","");
#ifdef __CYGWIN__
  Args = SealSetText(Args,"cacert","./cacert.crt");
#endif

  // Set default config file based on user's home.
  {
  char *s;
  s = getenv("XDG_CONFIG_HOME");
  if (s)
    {
    Args = SealSetText(Args,"config",s);
    }
  else
    {
    Args = SealSetText(Args,"config",getenv("HOME"));
    Args = SealAddText(Args,"config","/.config");
    }
  Args = SealAddText(Args,"config","/seal/config");
  Args = ReadCfg(Args);
  }

  // p and s are used with b to generate the hash.
  Args = SealSetIindex(Args,"@s",2,0); // sig offset in file [0]=start, [1]=end, [2]=number of signatures; default:zeros
  Args = SealSetIindex(Args,"@p",1,0); // previous sig offset in file [0]=start, [1]=end; default:[0,0]
  Args = SealSetText(Args,"@sflags"," "); // total range flags, set by SealDigest()
  Args = SealSetText(Args,"@sflags0"," "); // starting range flags, set by SealDigest()
  Args = SealSetText(Args,"@sflags1"," "); // ending range flags, set by SealDigest()

  // Read command-line
  int long_option_index;
  struct option long_options[] = {
    // Options match https://github.com/hackerfactor/SEAL/blob/master/SPECIFICATION.md
    {"help",      no_argument, NULL, 'h'},
    {"verbose",   no_argument, NULL, 'v'},
    {"version",   no_argument, NULL, 'V'},
    {"config",    required_argument, NULL, 9},
    {"generate",  no_argument, NULL, 'g'},
    {"genpass" ,  no_argument, NULL, 'G'},
    {"da",        required_argument, NULL, 'A'},
    {"digestalg", required_argument, NULL, 'A'},
    {"apikey",    required_argument, NULL, 'a'},
    {"apiurl",    required_argument, NULL, 1},
    {"cacert",    required_argument, NULL, 1}, // for specifying root PEMs
    {"cert-insecure", no_argument, NULL, 0}, // for ignoring TLS verification
    {"dnsfile",   required_argument, NULL, 'D'},
    {"domain",    required_argument, NULL, 'd'},
    {"id",        required_argument, NULL, 'i'},
    {"ka",        required_argument, NULL, 'K'},
    {"keyalg",    required_argument, NULL, 'K'},
    {"keybits",   required_argument, NULL, 1},
    {"keyfile",   required_argument, NULL, 'k'},
    {"Manual",    required_argument, NULL, 'M'},
    {"manual",    required_argument, NULL, 'm'},
    {"outfile",   required_argument, NULL, 'o'},
    {"options",   required_argument, NULL, 'O'},
    {"Sign",      no_argument, NULL, 'S'},
    {"sign",      no_argument, NULL, 's'},
    // long-only options
    {"sf",        required_argument, NULL, 1},
    {"kv",        required_argument, NULL, 1}, // must be numeric >= 0
    {"uid",       required_argument, NULL, 1},
    // informational
    {"info",      required_argument, NULL, 1},
    {"comment",   required_argument, NULL, 'c'},
    {"copyright", required_argument, NULL, 'C'},
    // source referencing
    {"src",       required_argument, NULL, 1}, // source url
    {"srca",      required_argument, NULL, 1}, // source digest encoding
    {"srcd",      required_argument, NULL, 1}, // source digest
    // modes
    {NULL,0,NULL,0}
    };
  while ((c = getopt_long(argc,argv,"A:a:C:c:D:d:ghi:K:k:M:m:o:O:Ssu:VvW?",long_options,&long_option_index)) != -1)
    {
    switch(c)
      {
      case 0: // generic longopt with no_argument
	Args = SealSetText(Args,long_options[long_option_index].name,"1");
	break;
      case 1: // generic longopt with required_argument (and no single-letter mapping)
	Args = SealSetText(Args,long_options[long_option_index].name,optarg);
	break;
      case 9: // read configuration file
	Args = SealSetText(Args,"config",optarg);
	Args = ReadCfg(Args);
	break;
      case 'A': Args = SealSetText(Args,"digestalg",optarg); break;
      case 'a': Args = SealSetText(Args,"apikey",optarg); break;
      case 'C': Args = SealSetText(Args,"copyright",optarg); break;
      case 'c': Args = SealSetText(Args,"info",optarg); break;
      case 'D': Args = SealSetText(Args,"dnsfile",optarg); break;
      case 'd': Args = SealSetText(Args,"domain",optarg); break;
      case 'i': Args = SealSetText(Args,"id",optarg); break;
      case 'K': Args = SealSetText(Args,"keyalg",optarg); break;
      case 'k': Args = SealSetText(Args,"keyfile",optarg); break;
      case 'o': Args = SealSetText(Args,"outfile",optarg); break;
      case 'O': Args = SealSetText(Args,"options",optarg); break;
      case 'u': Args = SealSetText(Args,"apiurl",optarg); break;

      case 'G': // generate password (not in usage; really insecure)
	Args = SealSetText(Args,"@genpass",optarg);
	break;

      case 'M': // manual remote signing
      case 'm': // manual local signing
	{
	if (optarg[0])
	  {
	  Args = SealSetText(Args,"@digest1",optarg);
	  SealHexDecode(SealSearch(Args,"@digest1")); // hex to binary
	  }
	}
	// fall through to Mode check
	__attribute__ ((fallthrough));
      case 'g': // generate flag
      case 'S': // signing flag: remote
      case 's': // signing flag: local
	if (Mode!='v') // if it's not the default value...
	  {
	  fprintf(stderr,"ERROR: Only one -g, -s, -S, -m, or -M permitted\n");
	  exit(0x80);
	  }
	Mode=c;
	break;

      case 'V': printf("%s\n",SEAL_VERSION); exit(0);
      case 'v': Verbose++; break;
      case 'W': WriteCfg(Args); break; // write the data as a config file
      case 'h': // help
      case '?': // help
        Usage(argv[0]); SealFree(Args); exit(0);
      default:
        Usage(argv[0]); SealFree(Args); exit(0x80);
      }
    } // while reading args

  // Idiot check values: No double-quotes!
  Args = SealParmCheck(Args);
  IsURL = SealIsURL(Args);
  IsLocal = SealIsLocal(Args);

  if (Mode=='g') // if generating keys
    {
    if (!SealSearch(Args,"dnsfile"))
	{
	Args = SealSetText(Args,"dnsfile","./seal-public.dns");
	}
    SealGenerateKeys(Args);
    return(ReturnCode); // done processing
    }

  // If signing, get dynamic signing parameters
  if (strchr("sSmM",Mode))
    {
    /*****
     When signing, no digest gets the size of the signature (@sigsize).
     This never changes between calls, so do it now.
     *****/
    if (IsURL && strchr("SM",Mode)) { Args = SealSignURL(Args); }
    else if (IsLocal && strchr("sm",Mode)) { Args = SealSignLocal(Args); }
    // Must have sigsize!
    if (SealGetU32index(Args,"@sigsize",0)==0)
	{
	fprintf(stderr,"ERROR: Unable to determine the signature size. Aborting.\n");
	exit(0x80);
	}
    Args = SealSetCindex(Args,"@mode",0,Mode);
    }
  else
    {
    Args = SealSetText(Args,"Mode","verify");
    }
  if (Verbose > 3) { DEBUGWALK("Post-CLI Parameters",Args); } // DEBUGGING

  // Manual processing (no files)
  if (strchr("Mm",Mode))
    {
    Seal_Manual(Args);
    return(ReturnCode); // done processing
    }

  // Process all args (files required)
  if (optind >= argc)
    {
    fprintf(stderr,"ERROR: No input files.\n");
    exit(0x80);
    }

  // Don't mess up command-line parameters
  CleanArgs = Args;
  Args=NULL;

  // Process command-line files.
  bool First=true;
  for( ; optind < argc; optind++)
    {
    // Start off with a clean set of parameters
    if (Args) { SealFree(Args); Args=NULL; }
    Args = SealClone(CleanArgs);

    // Show file being processed.
    if (First) { First=false; } else { printf("\n"); }
    printf("[%s]\n",argv[optind]);
    fflush(stdout);

    // Memory map the file; needed for finding the SEAL record's location.
    mmapfile *Mmap=NULL;
    Mmap = MmapFile(argv[optind],PROT_READ); // read-only
    if (!Mmap)
	{
	fprintf(stdout," ERROR: Unknown file '%s'. Skipping.\n",argv[optind]);
	continue;
	}

    // Identify the filename format
    if (Seal_isPNG(Mmap)) { FileFormat='P'; } // PNG
    else if (Seal_isJPEG(Mmap)) { FileFormat='J'; } // JPEG
    else if (Seal_isGIF(Mmap)) { FileFormat='G'; } // GIF
    else if (Seal_isRIFF(Mmap)) { FileFormat='R'; } // RIFF
    else if (Seal_isMatroska(Mmap)) { FileFormat='M'; } // Matroska
    else if (Seal_isBMFF(Mmap)) { FileFormat='B'; } // BMFF
    else if (Seal_isPDF(Mmap)) { FileFormat='p'; } // PDF
    else if (Seal_isTIFF(Mmap)) { FileFormat='T'; } // TIFF
    else if (Seal_isPPM(Mmap)) { FileFormat='m'; } // PPM/PGM
    else if (Seal_isDICOM(Mmap)) { FileFormat='D'; } // DICOM
    else if (Seal_isMPEG(Mmap)) { FileFormat='a'; } // MPEG
    else if (Seal_isAAC(Mmap)) { FileFormat='A'; } // AAC
    else if (Seal_isText(Mmap)) { FileFormat='x'; } // Text
    else
	{
	fprintf(stdout," ERROR: Unknown file format '%s'. Skipping.\n",argv[optind]);
	ReturnCode |= 0x02; // at least one file has no signature
	MmapFree(Mmap);
	continue;
	}

    // File exists! Now process it!
    if (strchr("sS",Mode)) // if signing local/remote
      {
      char *Outname, *Template;
      Template = (char*)(SealSearch(Args,"outfile")->Value);
      Outname = MakeFilename(Template,(char*)argv[optind]);
      if (!Outname) { continue; }
      Args = SealSetText(Args,"@FilenameOut",Outname);
      free(Outname);
      }

    // Process based on file format
    switch(FileFormat)
    	{
	case 'A': Args = Seal_AAC(Args,Mmap); break; // AAC
	case 'a': Args = Seal_MPEG(Args,Mmap); break; // MPEG
	case 'B': Args = Seal_BMFF(Args,Mmap); break; // BMFF
	case 'D': Args = Seal_DICOM(Args,Mmap); break; // DICOM
	case 'G': Args = Seal_GIF(Args,Mmap); break; // GIF
	case 'J': Args = Seal_JPEG(Args,Mmap); break; // JPEG
	case 'M': Args = Seal_Matroska(Args,Mmap); break; // Matroska
	case 'm': Args = Seal_PPM(Args,Mmap); break; // PPM/PGM
	case 'P': Args = Seal_PNG(Args,Mmap); break; // PNG
	case 'p': Args = Seal_PDF(Args,Mmap); break; // PDF
	case 'R': Args = Seal_RIFF(Args,Mmap); break; // RIFF
	case 'T': Args = Seal_TIFF(Args,Mmap); break; // TIFF
	case 'x': Args = Seal_Text(Args,Mmap); break; // Text
	default: break; // should never happen
	}

    if (SealGetIindex(Args,"@s",2)==0) // no signatures
	{
	ReturnCode |= 0x02; // at least one file has no signature
	}
    else if (Mode=='v') // Check final
	{
	SealVerifyFinal(Args);
	}

    if (Verbose > 1) { DEBUGWALK("Post-File Parameters",Args); } // DEBUGGING
    
    MmapFree(Mmap);
    if (Args) { SealFree(Args); Args=NULL; }
    } // foreach command-line file

  // Clean up
  SealFreePrivateKey(); // if a private key was allocated
  if (Args) { SealFree(Args); Args=NULL; }
  SealFree(CleanArgs); // free memory for completeness
  return(ReturnCode); // done processing
} /* main() */

