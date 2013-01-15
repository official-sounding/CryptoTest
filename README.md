#CryptoTest
This is a collection of different Crytography algorithms & protocols I've implemented to try to better understand them and also kill time

most of them come with a test suite that uses official test vectors (where available).  I've tried to cram them into something approximating a standardized interface

algorithms implemented include:

## Block Ciphers
* AES
* Blowfish
* Twofish

all block ciphers can use ECB or CBC operating modes

## Hashing Algorithms
* SHA256
* HMAC-SHA256

## Asymetrical Algorithms
* Lamport Signatures
* PKCS#1 v1.5 RSAES-OAEP (RSA works, and OAEP works, but thanks to some BigInteger strageness, their interaction doesn't work all that well)

## Card-based Algorithms
* Solitaire
* Mirdek

# Disclaimer
while everything other than PKCS#1 works and passes their respective test vectors, it is a very bad idea indeed to try to use these in any sort of production environment.  This code has not been vetted against any sort of side-channel or implementation attack.  

# License
All of the code in this project is licensed under a Simplified BSD License:

Copyright (c) 2012, Peter Elliott
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
