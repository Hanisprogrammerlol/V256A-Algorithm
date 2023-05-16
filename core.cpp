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
*
* this is the core of V256A
* V256A was designed for signature of VChain
* made by void
* 09/08/2022
* 
* V256A taking inspiration of sha256 and argon2
* thank you for sha256 and argon2 creator
* 
* known issues:
* -incompatible for 32bit platforms
* 
* fixed issues:
* -performance is better
* -memory leak issue is solved
* -calcchunk performance is better
* -fixed output will return blank string
* -(solved) because this core used sprintf the variable sometimes will cause buffer overflow (i didnt use sprintf_s because of some issues)
* -changed malloc into calloc because of undefined behaviour when hashing
* 
* current version:
* 1.4.5.bt1 Revision
* 
* warning!
* V256A has been tested on msvc2019 and g++, but not tested on clang and other compiler
* minimum ram size is 2048kb/2mb, recommended 8mb/32mb
* supported for x86 and x64 platforms, armv7 support coming soon!
* 
*/

//disable C4996 error for msvc compilers
#ifdef _MSVC_LANG
#pragma warning(disable: 4996)
#endif

#pragma optimize("O3, inline", on)
#ifdef _M_IX86
#define V256A_OPT __cdecl
#elif _M_X64
#define V256A_OPT __stdcall
#elif _M_ARM
//Armv7 support comming soon
#endif

#include <iostream>
#include <cstdlib>
#include <string>
#include <immintrin.h>
#include "core.hpp"

//V256A Struct Initialization
V256A_Constructor V256A_Cons;

//V256A Constants
extern V256A_Uint64_t V256A_Constants_A = 0x50;
extern V256A_Uint64_t V256A_Constants_B = 0xeb;
extern V256A_Uint64_t V256A_Constants_C = 0xc7;

//Initializer for V256A_GenerateHash() and V256A_CalcChunks
void V256A_Init(void) {
    //because this is V256 Which Uses 6digit/bit hex and array between 5 and 10 will become 0x0 for calc chunk purpose
    //V256A_Constructor cons;
    V256A_Cons.rfactor[0] += 0xce699e;
    V256A_Cons.rfactor[1] += 0x44a72d;
    V256A_Cons.rfactor[2] += 0x30b83d;
    V256A_Cons.rfactor[3] += 0x39a585;
    V256A_Cons.rfactor[4] += 0xa0b000;
}

//Chunk Calculator for V256A must call V256A_Init first before calling function
void V256A_CalcChunks(uint8_t asciicode) {
    //before calcchunks, call V256A_Init(); first to initialize default data
    register constexpr uint64_t ch[10]{
        0xfd2c64f92d42cfab, 0x25581188432fcc78, 0xf0a78705d3d0dcb1, 0xbe2339b2d97f789f,
        0xe65043773f9c3a9e, 0x4ec4de1fee1403f8, 0xc428ee3cbc51eba8, 0xfddaa39125bff3eb,
        0x2fe2133270548bf8, 0x47ad172ee39dc3aa

    };
    register uint64_t *temp1 = (uint64_t*)calloc(10, sizeof(uint64_t));
    for (uint32_t i = 0; i < 10; ++i) {
        temp1[i] += ch[i];
        temp1[i] += temp1[i] * 4;
        temp1[i] += temp1[i] * asciicode / 50;
        temp1[i] = temp1[i] >> 1;
        V256A_Cons.chunks[i] += temp1[i];
        V256A_Cons.rfactor[i + 5] += temp1[i] * V256A_Constants_B;
    }
    free(temp1);
    return;
};

void V256A_Digest(void) {
    register constexpr V256A_Uint16_t v[64]{
        0xc593, 0x29ae, 0x19fc, 0x70b0, 0x2dba,
        0x9a32, 0x290d, 0x8ec7, 0xa9f8, 0xb021,
        0x359a, 0xa00e, 0x7825, 0xcdb3, 0x52c4,
        0x826b, 0x65b9, 0x3318, 0x0ac2, 0xe543,
        0x8928, 0x5687, 0xf7b9, 0x5a9e, 0x8549,
        0x02b7, 0xc3fc, 0xaa62, 0xd4e2, 0x2bae,
        0x7a4f, 0x2d19, 0x8812, 0x4069, 0x3fc6,
        0x6017, 0x8308, 0xdaf2, 0x9409, 0x5167,
        0x9413, 0x164c, 0xa77d, 0x8d0c, 0x65e7,
        0x6393, 0x3ec7, 0x243e, 0xd84a, 0x6c79,
        0x299a, 0xe52d, 0xf3b1, 0xb851, 0x4205,
        0x15d6, 0x468f, 0x17c0, 0x4984, 0x680f,
        0xf14c, 0x8e50, 0xe9b8, 0x7794
    };
    for (uint32_t i = 0; i < 64; ++i) {
        V256A_Cons.digest_size[i] += v[i] * 4 >> 32 ^ 2;
    }
}

//additional salting system for V256A
void V256A_Mixins(char* hash, char* output, uint8_t mixin_mapping[6]) {
    const uint8_t mixin_table[24] = {34, 38, 36, 43, 47, 63,
                               34, 38, 36, 43, 47, 63, 
                               34, 38, 36, 43, 47, 63, 
                               34, 38, 36, 43, 47, 63};
    register char* temp = (char*)calloc(2048, sizeof(char));
    register char temp2[2048] = { 0x0 };
    for (int i = 0; i < 24; ++i) {
        V256A_Cons.curr_mixins[i] = hash[i];
    }
    for (int i = 0; i < 6; ++i) {
        V256A_Cons.curr_mixins[mixin_mapping[i]] = mixin_table[mixin_mapping[i]];
    }
    for (uint16_t i = 0; i < 24; ++i) {
        sprintf(temp, "%I64x", V256A_Cons.curr_mixins[i]);
        strcat(temp2, &temp[i]);
    }
    free(temp);
    memcpy(output, temp2, 24);
};

//Generate V256A Hash But Call V256A_Init() and V256A_CalcChunks() first
void V256A_OPT V256A_GenerateHash(const char *msg, uint16_t rotation, uint16_t xor_rotator, uint16_t hash_obsfuscation) {
    V256A_Text *tempmsg = (V256A_Text*)calloc(24, sizeof(V256A_Text));
    register V256A_Uint64_t datstrhash = 0;
    V256A_Uint64_t mlen = 0;
    //checking for parameters
    if (hash_obsfuscation < 128) {
        return throw "Hash Obsfuscation Must Be Up To 128bit";
    }
    if (hash_obsfuscation > 512) {
        return throw "Hash Obsfuscation Must Be Smaller Than 512bit";
    }
    if (rotation < 1) {
        return throw "Rotation Must Be Up To 1";
    }
    if (rotation > 128) {
        return throw "Rotation Must Be Smaller Than 4";
    }
    if (xor_rotator < 1) {
        return throw "Xor Rotator Must Be Up To 1";
    }
    if (xor_rotator > 32) {
        return throw "Xor Rotator Must Be Smaller Than 32 (for memory safety)";
    }
    //start checking V256A_Init, V256A_CalcChunks and V256A_Digest
    if (V256A_Cons.rfactor[0] == 0) {
        return throw "rfactor is not initialized: rfactor returned 0x0"; // rfactor is not initialized
    }
    if (V256A_Cons.rfactor[5] == 0) {
        return throw "rfactor is not calculated: rfactor returned 0x0"; // rfactor chunks is not calculated
    }if (V256A_Cons.chunks[0] == 0) {
        return throw "chunks is not calculated: chunks returned 0x0"; // chunks is not calculated
    }
    if (V256A_Cons.digest_size[0] == 0) {
        return throw "digest_size is not digested: digest_size returned 0x0"; // digest_size is not digested
    }
    //overwrite data
    memcpy(tempmsg, msg, sizeof(tempmsg));
    //because of some changes V256A will have 16 different hex for better performance
    for (uint16_t i = 0; i < 24; i++) {
        datstrhash = tempmsg[i] >> i * rotation;
        datstrhash = datstrhash << 2 >> 4 << 1 >> rotation + hash_obsfuscation;
        datstrhash = datstrhash ^ xor_rotator + 1;
        datstrhash = datstrhash >> mlen << 4 >> 2 ^ xor_rotator;
        datstrhash = datstrhash ^ 64;
        datstrhash = datstrhash << 2;
        datstrhash = datstrhash | 2;
        datstrhash = datstrhash >> 4;
        datstrhash = datstrhash ^ 4 ^ 3 ^ 2 >> 1 & 4 ^ 5 | 3 << 3 >> 4 << 6 ^ 2 >> 1;
        datstrhash = datstrhash + V256A_Cons.rfactor[i] >> 2;
        datstrhash = datstrhash / V256A_Cons.digest_size[i];
        datstrhash = datstrhash + V256A_Cons.chunks[i] / 2;
        datstrhash = datstrhash ^ V256A_Cons.digest_size[i + xor_rotator];
        datstrhash = datstrhash * strlen(msg);
        V256A_Cons.curr_hash[i] += datstrhash / 6;
    }
    free(tempmsg);
    if (strlen(msg) > 24) { V256A_Cons.mixin_table[0] = strlen(msg) - strlen(msg) + 6; }
    V256A_Cons.mixin_table[1] = int(V256A_Cons.curr_hash[0]); V256A_Cons.mixin_table[2] = int(V256A_Cons.curr_hash[5]) + 2;
    V256A_Cons.mixin_table[3] = int(&msg[0]); V256A_Cons.mixin_table[4] = int(&msg[strlen(msg) - 1]); V256A_Cons.mixin_table[5] = xor_rotator/4;
    return;
};

//reworked V256A prototype for AVX platforms
void V256A_OPT V256A_GenerateHash_AVX(const char* msg, uint16_t rotation, uint16_t xor_rotator, uint16_t hash_obsfuscation) {
    V256A_Text* tempmsg = (V256A_Text*)calloc(24, sizeof(V256A_Text));
    //V256A_Uint64_t datstrhash = 0;
    register __m128i datstrhash = _mm_set1_epi64x(0);
    __m128i mlen = _mm_set1_epi64x(0);
    for (uint16_t i = 0; i < 24; i++) {
        datstrhash.m128i_u64[0] = tempmsg[i] >> i * rotation;
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] << 2 >> 4 << 1 >> rotation + hash_obsfuscation;
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] ^ xor_rotator + 1;
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] >> mlen.m128i_u64[0] << 4 >> 2 ^ xor_rotator;
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] ^ 64;
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] << 2;
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] | 2;
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] >> 4;
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] ^ 4 ^ 3 ^ 2 >> 1 & 4 ^ 5 | 3 << 3 >> 4 << 6 ^ 2 >> 1;
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] + V256A_Cons.rfactor[i] >> 2;
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] / V256A_Cons.digest_size[i];
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] + V256A_Cons.chunks[i] / 2;
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] ^ V256A_Cons.digest_size[i + xor_rotator];
        datstrhash.m128i_u64[0] = datstrhash.m128i_u64[0] * strlen(msg);
        V256A_Cons.curr_hash[i] += datstrhash.m128i_u64[0] / 6;
    }
    free(tempmsg);
    if (strlen(msg) > 24) { V256A_Cons.mixin_table[0] = strlen(msg) - strlen(msg) + 6; }
    V256A_Cons.mixin_table[1] = int(V256A_Cons.curr_hash[0]); V256A_Cons.mixin_table[2] = int(V256A_Cons.curr_hash[5]) + 2;
    V256A_Cons.mixin_table[3] = int(&msg[0]); V256A_Cons.mixin_table[4] = int(&msg[strlen(msg) - 1]); V256A_Cons.mixin_table[5] = xor_rotator / 4;
    return;
}

//last process to call before V256A_Sweep() and after V256A_GenerateHash()
//x86 use __cdecl and x64 use __stdcall
void V256A_OPT V256A_ProcessHash(char* output) {
    register char* temp = (char*)calloc(24, 24); //every memory count holds 24 byte of hex
    register char* temp2 = (char*)calloc(24, 24);
    register constexpr uint64_t rnf[24] = {
        0xb5f0d8a276e1217e, 0x3b9a344c204773bb, 0x21c90dd3947d20e1, 0xeffd0ff46673395d,
        0xf659babc19db37e0, 0x8bfe034635a03780, 0x3794e110a37cbce3, 0xf06d93c33c462c1e,
        0x83848946966d22ee, 0xb10308c3b2f5bc8b, 0xaeea9fc976b4730e, 0x41e8e7ffa44e2d32,
        0x8fbd0d04fd765535, 0x730f76da6f27b69b, 0x7addd82abb8a328e, 0xda2469f78f9a077a,
        0xc9172144bbe4be76, 0xc5056fa23d95cc26, 0xc674ab49cd2c5848, 0xd8a71ee2f4873f4b,
        0x3181afd67b0c3ba7, 0xbda094b8c45aa6e9, 0x6416c8d8583fad4f, 0xb022126829b1b3ea
    };
    for (uint16_t i = 0; i < 24; ++i) {
        sprintf(temp, "%I64x", (uint64_t)(V256A_Cons.curr_hash[i] * V256A_Cons.curr_hash[i] * V256A_Cons.rfactor[i] + V256A_Constants_A + rnf[i]));
        strcat(&temp2[i], &temp[i]);
    }
    //memcpy_s(&output, 48, temp2, 48);
    strncpy(output, temp2, 48);
    return;
    free(temp);free(temp2);
}

//reset chunks, rfactor, curr_hash, digest_size
void V256A_Sweep(void) {
    for (uint16_t i = 0; i < 10; ++i) {
        V256A_Cons.rfactor[i] = 0x0;
        V256A_Cons.chunks[i] = 0x0;
    }
    for (uint16_t i = 0; i < 16; ++i) {
        V256A_Cons.curr_hash[i] = 0x0;
        V256A_Cons.curr_mixins[i] = 0x0;
    }
    for (uint16_t i = 0; i < 64; ++i) {
        V256A_Cons.digest_size[i] = 0x0;
    }
};