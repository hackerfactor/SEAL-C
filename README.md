# SEAL-C
SEAL is a Secure Evidence Attribution Label. It permits signing media for attribution. The specifications are at: https://github.com/hackerfactor/SEAL

This is an implementation of SEAL in C.

This code:
1. Generates keys. The private key should be kept private. The public key is ready to be uploaded to your DNS TXT record.
2. Sign files using the private key. It also supports using a remote signing service.
3. Valiating signatures. This only requires DNS access. For testing/debugging, you can specify the public key DNS TXT file that you generated.

See the [BUILD](BUILD.md) file for compiling and usage.
