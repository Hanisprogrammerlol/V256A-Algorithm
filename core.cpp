/*
* this is the core of V256A
* V256A was designed for signature of VChain
* made by void
* 09/08/2022
* 
* V256A taking inspiration of sha256 and argon2
* thank you for sha256 and argon2 creator
* 
* known issues:
* -suck af horibble performance
* -when generating the same text with same rot, xor and obs will output different hash
* 
* fixed issues:
* -memory leak issue go bye bye
* -calcchunk performance getting good
* 
*/

#include <iostream>
#include <cstdlib>
#include "core.h"


//Initializer for V256A_GenerateHash() and V256A_CalcChunks
void V256A_Init(void) {
    //because this is V256 Which Uses 6digit/bit hex and array between 5 and 10 will become 0x0 for calc chunk purpose
    V256A_Constructor* cons;
    cons = (V256A_Constructor*)malloc(sizeof(V256A_Constructor));
    cons->rfactor[0] += 0xce699e;
    cons->rfactor[1] += 0x44a72d;
    cons->rfactor[2] += 0x30b83d;
    cons->rfactor[3] += 0x39a585;
    cons->rfactor[4] += 0xa0b000;
    free(cons);
    /*for (uint16_t i = 0; i < 10; i++) {
        std::cout << cons->rfactor[i] << "-\n";
    }*/
}

//Chunk Calculator for V256A must call V256A_Init first before calling function
void V256A_CalcChunks(uint16_t asciicode) {
    //before calcchunks, call V256A_Init(); first to initialize default data
    V256A_Constructor cons;
    const static uint32_t ch[10]{
        0xfd2c64f92d42cfab, 0x25581188432fcc78, 0xf0a78705d3d0dcb1, 0xbe2339b2d97f789f,
        0xe65043773f9c3a9e, 0x4ec4de1fee1403f8, 0xc428ee3cbc51eba8, 0xfddaa39125bff3eb,
        0x2fe2133270548bf8, 0x47ad172ee39dc3aa

    };
    //uint32_t temp1[10];
    uint32_t* temp1 = (uint32_t*)malloc(10 * sizeof(uint32_t));
    uint32_t *temp2 = (uint32_t*)malloc(5 * sizeof(uint32_t));
    temp2[0] += cons.rfactor[0];
    temp2[1] += cons.rfactor[1];
    temp2[2] += cons.rfactor[2];
    temp2[3] += cons.rfactor[3];
    temp2[4] += cons.rfactor[4];
    for (uint32_t i = 0; i < 10; ++i) {
        temp1[i] += ch[i];
        temp1[i] += temp1[i] * 4;
        temp1[i] += temp1[i] * asciicode;
        temp1[i] = temp1[i] >> 1;
        cons.chunks[i] += temp1[i];
        cons.rfactor[i + 5] += temp1[i];
    }
    for (uint32_t i = 0; i < 5; ++i) {
        temp2[i] = cons.rfactor[i] + temp2[i];
        temp2[i] = NULL;
    }
    for (uint32_t i = 0; i < 10; ++i) {
        std::cout << temp2[i] << "\n";
        //std::cout << temp2[i] << "\n";
    }
    free(temp1);
    free(temp2);
    return;
};

//Generate V256A Hash But Call V256A_Init() and V256A_CalcChunks() first
void V256A_GenerateHash(const char *msg, uint16_t rotation, uint16_t xor_rotator, uint16_t hash_obsfuscation) {
    //initializing vars
    const static uint64_t binsalt[52] = {
         01100001, 01100010, 01100011, 01100100,
         01100101, 01100110, 01100111, 01101000,
         01101001, 01101010, 01101011, 01101100,
         01101101, 01101110, 01101111, 01110000,
         01110001, 01110010, 01110011, 01110100,
         01110101, 01110110, 01110111, 01111000,
         01111001, 01111010,
         01000001, 01000010, 01000011, 01000100,
         01000101, 01000110, 01000111, 01001000,
         01001001, 01001010, 01001011, 01001100,
         01001101, 01001110, 01001111, 01010000,
         01010001, 01010010, 01010011, 01010100,
         01010101, 01010110, 01010111, 01011000,
         01011001, 01011010
    };
    uint64_t datstrhash = 0;
    uint64_t mlen = 0;
    if (hash_obsfuscation < 128) {
        return throw std::invalid_argument("Hash Length Must Be Up To 128bit");
    }
    if (hash_obsfuscation > 512) {
        return throw std::invalid_argument("Hash Length Must Be Smaller Than 1024bit");
    }
    if (rotation < 1) {
        return throw std::invalid_argument("Rotation Must Be Up To 1");
    }
    if (rotation > 128) {
        return throw std::invalid_argument("Rotation Must Be Smaller Than 4");
    }
    if (xor_rotator < 1) {
        return throw std::invalid_argument("Xor Rotator Must Be Up To 1");
    }
    if (xor_rotator > 32) {
        return throw std::invalid_argument("Xor Rotator Must Be Smaller Than 32 (for memory safety)");
    }
    mlen = strlen(msg);
    printf("V256A#ROT=%i#XOR=%i#OBS=%i#", rotation, xor_rotator, hash_obsfuscation);
    //because of some changes V256A will have 16 different hex for better performance
    for (uint32_t i = 0; i < 16; i++) {
        datstrhash = msg[i] >> i + rotation;
        datstrhash = datstrhash << 2 >> 4 << 1 >> rotation + hash_obsfuscation;
        datstrhash = datstrhash ^ xor_rotator + 1;
        datstrhash = datstrhash >> mlen << 4 >> 2 ^ xor_rotator;
        datstrhash = datstrhash ^ binsalt[i + rotation + 1 - 1];
        datstrhash = datstrhash << binsalt[i * rotation];
        datstrhash = datstrhash | 2;
        datstrhash = datstrhash >> 4;
        datstrhash = datstrhash ^ 4 ^ 3 ^ 2 >> 1 & 4 ^ 5 | 3 << 3 >> 4 << 6 ^ 2 >> 1;
        std::cout << std::hex << datstrhash;
    }
    return;
};

void Rnall(void) {
    V256A_Init();
    V256A_CalcChunks(109);
    //V256A_Constructor cons;
    /*for (uint16_t i = 0; i < 10; i++) {
        std::cout << cons.rfactor[i] << "-\n";
    }*/
}