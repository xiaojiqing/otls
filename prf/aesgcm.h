#ifndef _AES_GCM_H_
#define _AES_GCM_H_
#include "emp-tool/emp-tool.h"
using namespace emp;

static block R = makeBlock(0xe100000000000000, 0x00);

inline block rsht(block x, size_t i) {
    uint64_t* data = (uint64_t*)&x;
    if (i == 0) {
        return x;
    } else if (i < 64) {
        return makeBlock((data[1] >> i), (data[1] << (64 - i)) ^ (data[0] >> i));
    } else if (i < 128) {
        return makeBlock(0x00, data[1] >> (i - 64));
    } else
        return makeBlock(0x00, 0x00);
}

inline block mulBlock(block x, block y) {
    block Z = zero_block, V = y;

    for (int i = 0; i < 128; i++) {
        Z = getLSB(rsht(x, 127 - i)) ? Z ^ V : Z;
        V = getLSB(V) ? rsht(V, 1) ^ R : rsht(V, 1);
    }
    return Z;
}

#endif