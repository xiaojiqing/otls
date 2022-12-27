#include "sha256.h"
#include <iostream>
#include <string>
#include "emp-tool/emp-tool.h"
#include "utils.h"
#include <vector>

using namespace std;
using namespace emp;
using std::vector;

void SHA_256::padding(Integer& padded_input, const Integer input) {
    uint64_t L = input.size();

    long long K = (uint64_t)CHUNKLEN - 65 - L;
    while (K < 0) {
        K += CHUNKLEN;
    }

    Integer ONE(1, 1, PUBLIC);
    Integer INTK(K, 0, PUBLIC);
    Integer INTL(64, L, PUBLIC);

    padded_input = input;
    concat(padded_input, &ONE, 1);
    concat(padded_input, &INTK, 1);
    concat(padded_input, &INTL, 1);
}

void SHA_256::update(Integer* dig, const Integer padded_input) {
    uint64_t padded_len = padded_input.size();
    if (padded_len % CHUNKLEN == 0) {
        Integer tmp = Integer(WORDLEN, (int)0, PUBLIC);
        vector<Integer> input_data;
        for (int i = padded_input.size() - 1; i >= 0; --i) {
            tmp.bits[i % WORDLEN] = padded_input[i];

            if (i % WORDLEN == 0) {
                input_data.push_back(tmp);
            }
        }

        uint64_t num_chunk = padded_len / CHUNKLEN;
        for (int i = 0; i < VALLEN; i++)
            dig[i] = sha256_h[i];

        Integer* tmp_block = new Integer[CHUNKLEN / WORDLEN]; //CHUNKLEN/WORDLEN=16
        for (uint64_t i = 0; i < num_chunk; i++) {
            for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
                tmp_block[j] = input_data[j + i * CHUNKLEN / WORDLEN];
            }
            chunk_compress(dig, tmp_block);
        }
        delete[] tmp_block;
    } else
        error("wrong padding length!\n");
}

void SHA_256::opt_update(uint32_t* plain_dig, const Integer sec_input, unsigned char* pub_input, size_t pub_len) {
    uint64_t len = sec_input.size();
    if (len == CHUNKLEN) {
        Integer tmp = Integer(WORDLEN, (int)0, PUBLIC);
        vector<Integer> input_data;
        for (int i = len - 1; i >= 0; --i) {
            tmp.bits[i % WORDLEN] = sec_input[i];

            if (i % WORDLEN == 0) {
                input_data.push_back(tmp);
            }
        }

        Integer* dig = new Integer[VALLEN];
        for (int i = 0; i < VALLEN; i++)
            dig[i] = sha256_h[i];

        chunk_compress(dig, input_data.data());

        for (int i = 0; i < VALLEN; i++) {
            plain_dig[i] = dig[i].reveal<uint32_t>(PUBLIC);
        }

        delete[] dig;

        unsigned char* data = new unsigned char[KLEN];
        size_t datalen = 0, bitlen = 512;

        for (size_t i = 0; i < pub_len; i++) {
            data[datalen] = pub_input[i];
            datalen++;
            if (datalen == 64) {
                opt_chunk_compress(plain_dig, data);
                bitlen += 512;
                datalen = 0;
            }
        }

        size_t i = datalen;

        if (datalen < 56) {
            data[i++] = 0x80;
            while (i < 56)
                data[i++] = 0x00;
        } else {
            data[i++] = 0x80;
            while (i < 64)
                data[i++] = 0x00;
            opt_chunk_compress(plain_dig, data);
            memset(data, 0, 56);
        }

        bitlen += datalen * 8;
        data[63] = bitlen;
        data[62] = bitlen >> 8;
        data[61] = bitlen >> 16;
        data[60] = bitlen >> 24;
        data[59] = bitlen >> 32;
        data[58] = bitlen >> 40;
        data[57] = bitlen >> 48;
        data[56] = bitlen >> 56;
        opt_chunk_compress(plain_dig, data);

        delete[] data;

    } else
        error("wrong secret input length!\n");
}
void SHA_256::chunk_compress(Integer* input_h, Integer* chunk) { //chunk consists of 16 words with 32bit each
    Integer* w = new Integer[KLEN];
    for (int i = 0; i < CHUNKLEN / WORDLEN; i++) //initiate w
        w[i] = chunk[i];
    for (int i = 16; i < KLEN; i++) {
        Integer s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3);
        Integer s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    Integer a = input_h[0], b = input_h[1], c = input_h[2], d = input_h[3], e = input_h[4], f = input_h[5], g = input_h[6], h = input_h[7]; //working variables

    Integer S1, ch, temp1, S0, maj, temp2;

    for (int i = 0; i < KLEN; i++) { //compression function main loop
        S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
        //    ch = (e&f)^((e^ONE)&g);
        ch = (e & (f ^ g)) ^ g;
        temp1 = h + sha256_k[i] + S1 + ch + w[i]; //22009 AND
        //    temp1 = h+sha256_k[i]+w[i]+S1+ch;//22070 AND
        //    temp1 = h+sha256_k[i]+S1+w[i]+ch;//22038 AND
        //    temp1 = ((sha256_k[i]+w[i])+h)+S1+ch;
        S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
        //    maj = (a&b)^(a&c)^(b&c);
        //    maj = (a&(b^c))^(b&c);
        maj = ((a ^ b) & (a ^ c)) ^ a;
        temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    input_h[0] = a + input_h[0];
    input_h[1] = b + input_h[1];
    input_h[2] = c + input_h[2];
    input_h[3] = d + input_h[3];
    input_h[4] = e + input_h[4];
    input_h[5] = f + input_h[5];
    input_h[6] = g + input_h[6];
    input_h[7] = h + input_h[7];

    delete[] w;
}

void SHA_256::opt_chunk_compress(uint32_t* input_h, unsigned char* chunk) { // length of chunk is 64;
    uint32_t* w = new uint32_t[KLEN];
    for (int i = 0, j = 0; i < 16; i++, j += 4) //initiate w
        w[i] = (chunk[j] << 24) | (chunk[j + 1] << 16) | (chunk[j + 2] << 8) | chunk[j + 3];

    for (int i = 16; i < KLEN; i++) {
        uint32_t s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = input_h[0], b = input_h[1], c = input_h[2], d = input_h[3], e = input_h[4], f = input_h[5], g = input_h[6], h = input_h[7]; //working variables

    uint32_t S1, ch, temp1, S0, maj, temp2;

    for (int i = 0; i < KLEN; i++) { //compression function main loop
        S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
        ch = (e & (f ^ g)) ^ g;
        temp1 = h + plain_sha256_k[i] + S1 + ch + w[i];
        S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
        maj = ((a ^ b) & (a ^ c)) ^ a;
        temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    input_h[0] = a + input_h[0];
    input_h[1] = b + input_h[1];
    input_h[2] = c + input_h[2];
    input_h[3] = d + input_h[3];
    input_h[4] = e + input_h[4];
    input_h[5] = f + input_h[5];
    input_h[6] = g + input_h[6];
    input_h[7] = h + input_h[7];
    delete[] w;
}
void SHA_256::digest(Integer* res, Integer input) {
    Integer padded_input;
    padding(padded_input, input);
    update(res, padded_input);
}

void SHA_256::opt_digest(uint32_t* res, const Integer sec_input, unsigned char* pub_input, size_t pub_len) { opt_update(res, sec_input, pub_input, pub_len); }
