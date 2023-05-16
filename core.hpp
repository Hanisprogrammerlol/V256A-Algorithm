/*
* MIT License
*
* Copyright (c) 2022 Hanisprogrammerlol
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#ifndef CORE_HPP
#define CORE_HPP

/* These macros only used in Revision 1.4.4 and below
//V256A_OUTPUTSIZE_S is used on common V256A hashing (hashing with 0-8192 char text length with allocated 256 byte of memory)
#define V256A_OUTPUTSIZE_S 256
//V256A_OUTPUTSIZE_B is used on complex V256A hashing (hashing with 8192-16384 char text length with allocated 512 byte of memory)
#define V256A_OUTPUTSIZE_B 512
//V256A_OUTPUTSIZE_H is used on very complex V256A hashing (hashing with 16384-(probably around 40k) char text length with allocated 1024 byte of memory)
#define V256A_OUTPUTSIZE_H  1024
//V256A_OUTPUTSIZE_HH is used on very very complex V256A hashing with allocated 2048 byte of memory
#define V256A_OUTPUTSIZE_HH  2048
*/

#ifdef _M_IX86
#define V256A_OUTPUT 48
#elif _M_X64
#define V256A_OUTPUT 48
#endif

#include <iostream>

//V256A Custom Type

//V256A Text Format
typedef unsigned char V256A_Text;
//V256A Uint16_t Format
typedef unsigned short V256A_Uint16_t;
//V256A Uint64 Format
typedef unsigned long long int V256A_Uint64_t;

//Constructor for V256A (rfactor, chunks and prevhash as default is 0x0)
typedef struct V256A_Constructor {
	uint8_t mixin_table[6] = {
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0
	};
	V256A_Uint64_t rfactor[10] = {
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0
	};
	uint32_t chunks[10] = {
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0
	};
	V256A_Uint16_t digest_size[64]{
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0
	};
	uint64_t curr_mixins[24] = {
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0
	};
	uint64_t curr_hash[24] = {
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0
	};
};

void V256A_Init(void);
void V256A_CalcChunks(uint8_t asciicode);
void V256A_Digest(void);
void V256A_Mixins(char* hash, char* output, uint8_t mixin_mapping[6]);
void V256A_GenerateHash(const char* msg, uint16_t rotation, uint16_t xor_rotator, uint16_t hash_obsfuscation);
void V256A_ProcessHash(char* output);
void V256A_Sweep(void);

//prototype functions
void V256A_GenerateHash_AVX(const char* msg, uint16_t rotation, uint16_t xor_rotator, uint16_t hash_obsfuscation);

class V256A {
	public:
		static void CreateHash(const char* text, char* output, uint16_t rotation, uint16_t xor_rotator, uint16_t hash_obsfuscation) {
			V256A_Init();
			V256A_Digest();
			V256A_CalcChunks(text[0]);
			V256A_GenerateHash(text, rotation, xor_rotator, hash_obsfuscation);
			V256A_ProcessHash(output);
			V256A_Sweep();
		}
		static void __fastcall CreateHash_x86(const char* text, char* output, uint16_t rotation, uint16_t xor_rotator, uint16_t hash_obsfuscation) {
			V256A_Init();
			V256A_CalcChunks(text[0]);
			V256A_Digest();
			V256A_GenerateHash(text, rotation, xor_rotator, hash_obsfuscation);
			V256A_ProcessHash(output);
			V256A_Sweep();
		}
};

#endif