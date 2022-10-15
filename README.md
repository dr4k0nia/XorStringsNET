# XorStringsNET
A tool for simple and quick XOR based string encryption of .NET binaries

XORStrings implements a simple XOR based cipher, I call RXOR. RXOR does not only encrypt the string but also reverses its character order. Each string is encrypted with a unique key. The arguments used by the decryption routine are also XOR encrypted.

## How does it works?

`XorStrings.exe <path to file>`

Either use the commandline or drag & drop the to be obfuscated binary on the XorStrings executable.


