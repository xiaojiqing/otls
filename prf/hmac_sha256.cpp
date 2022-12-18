#include "emp-tool/emp-tool.h"
#include <iostream>
#include <vector>
#include "hmac_sha256.h"

void HMAC_SHA_256::init(Integer key) {
    Integer pad_key;

    if (key.size() > CHUNKLEN) {
        Integer* tmp = new Integer[DIGLEN];
        digest(tmp, key);
        SHA256_call++;
        pad_key = Integer(CHUNKLEN, 0, PUBLIC);
        for (int i = 0; i < DIGLEN; i++) {
            for (int j = 0; j < WORDLEN; j++) {
                pad_key.bits[j + i * WORDLEN] = tmp[DIGLEN - 1 - i].bits[j];
            }
        }
        pad_key = pad_key << (CHUNKLEN - DIGLEN * WORDLEN);

        delete[] tmp;
    }
    if (key.size() <= CHUNKLEN) {
        pad_key = Integer(CHUNKLEN, 0, PUBLIC);
        for (int i = 0; i < key.size(); i++)
            pad_key.bits[i] = key.bits[i];

        pad_key = pad_key << (CHUNKLEN - key.size());
    }

    Integer hex5C = Integer(CHUNKLEN, 0x5c, PUBLIC);
    Integer hex36 = Integer(CHUNKLEN, 0x36, PUBLIC);
    o_pad = Integer(CHUNKLEN, 0x5c, PUBLIC);
    i_pad = Integer(CHUNKLEN, 0x36, PUBLIC);

    for (int i = 0; i < CHUNKLEN / 8 - 1; i++) {
        o_pad = (o_pad << 8) ^ hex5C;
        i_pad = (i_pad << 8) ^ hex36;
    }
    o_key_pad = pad_key ^ o_pad;
    i_key_pad = pad_key ^ i_pad;
}

void HMAC_SHA_256::hmac_sha_256(Integer* dig, Integer key, Integer msg) {
    init(key);
    Integer i_msg = Integer(CHUNKLEN + msg.size(), 0, PUBLIC);
    for (int i = 0; i < msg.size(); i++) {
        i_msg.bits[i] = msg.bits[i];
    }
    for (int i = 0; i < CHUNKLEN; i++) {
        i_msg.bits[i + msg.size()] = i_key_pad.bits[i];
    }

    Integer* tmp_dig = new Integer[DIGLEN];
    digest(tmp_dig, i_msg);
    SHA256_call++;
    Integer o_msg = Integer(WORDLEN * DIGLEN + CHUNKLEN, 0, PUBLIC);
    for (int i = 0; i < CHUNKLEN; i++) {
        o_msg.bits[i] = o_key_pad.bits[i];
    }
    o_msg = o_msg << (WORDLEN * DIGLEN);
    for (int i = 0; i < DIGLEN; i++) {
        for (int j = 0; j < WORDLEN; j++) {
            o_msg.bits[j + i * WORDLEN] = tmp_dig[DIGLEN - 1 - i].bits[j];
        }
    }

    digest(dig, o_msg);
    SHA256_call++;

    delete[] tmp_dig;
}
