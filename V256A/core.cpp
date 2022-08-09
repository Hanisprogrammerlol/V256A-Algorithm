/*this is the core of V256A
* V256A was designed for signature of VChain
* made by void
* 09/08/2022
*/

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <inttypes.h>

#ifdef _WIN32
#include <Windows.h>
#endif // _win32

static void V256A_GenerateHash(const char *msg, uint16_t rotation, uint16_t xor_rotator, uint16_t hash_obsfuscation) {
    const static uint64_t binsalt[64] = {
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
    bool hashing_stat = false;
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
    for (uint32_t i = 0; i < strlen(msg); i++) {
        datstrhash = msg[i] >> i + rotation;
        datstrhash = datstrhash << 2 >> 4 << strlen(msg) >> rotation + hash_obsfuscation;
        datstrhash = datstrhash ^ xor_rotator + 1;
        datstrhash = datstrhash >> mlen << 16 >> 2 ^ xor_rotator;
        datstrhash = datstrhash ^ binsalt[i + rotation + 1 - 1];
        std::cout << datstrhash;
    }
    datstrhash = NULL;
    mlen = NULL;
    return;
};

/*datstrhash[i] = datstrhash[i] ^ binsalt[i + rotation + 1 - 1];
        datstrhash[i] = datstrhash[i] >> hash_length ^ binsalt[i + 128 - rotation];*/
        //tempdata + datstrhash[i];
