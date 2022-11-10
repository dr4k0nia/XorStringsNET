# XorStringsNET
A tool for simple and quick XOR based string encryption of .NET binaries

XORStrings implements a simple XOR based cipher, I call RXOR. RXOR does not only encrypt the string but also reverses its character order. Each string is encrypted with a unique key. The arguments used by the decryption routine are also XOR encrypted.

## How does it work?

`XorStrings.exe <path to file>`

Either use the commandline or drag & drop the to be obfuscated binary on the XorStrings executable.
XORStrings does support .NET Framework 4.6+ and .NET Core up to .NET

## More details

If you want a more detailed explanation of how XorStringsNET works checkout [my blog post](https://dr4k0nia.github.io/posts/Encrypting-Strings-In-NET/) were I explain the runtime and obfuscator in great detail 


