#include "sha256.h"
#include <iostream>
#include <string>
#include "emp-tool/emp-tool.h"
#include "utils.h"
#include <vector>

using namespace std;
using namespace emp;
using std::vector;

void SHA_256::padding(vector<Integer>& input_data, Integer input) {
    uint64_t L = input.size();

    long long K = (uint64_t)CHUNKLEN - 65 - L;
    while (K < 0) {
        K += CHUNKLEN;
    }

    uint64_t padded_len = (uint64_t)K + 65 + L;

    Integer _input = Integer(padded_len, 0, PUBLIC);

    for (uint64_t i = 0; i < (uint64_t)input.size(); i++) {
        _input.bits[i] = input.bits[i];
    }
    _input = (_input << 1);
    _input.bits[0] = Bit(true, PUBLIC);
    _input = _input << K;
    _input = (_input << 64);
    for (int i = 0; i < 64; i++) {
        _input.bits[i] = Bit((L >> i) % 2 == 1, PUBLIC);
    }

    Integer tmp = Integer(WORDLEN, (int)0, PUBLIC);

    for (int i = padded_len - 1; i >= 0; --i) {
        tmp.bits[i % WORDLEN] = _input.bits[i];

        if (i % WORDLEN == 0) {
            input_data.push_back(tmp);
        }
    }
}

void SHA_256::update(Integer* dig, vector<Integer> input_data) { //CHUNKLEN = 512,WORDLEN =32
    uint64_t padding_len = input_data.size() * WORDLEN;
    if (padding_len % CHUNKLEN == 0) {
        uint64_t num_chunk = padding_len / CHUNKLEN;
        for (int i = 0; i < VALLEN; i++)
            dig[i] = sha256_h[i];

        Integer* tmp = new Integer[CHUNKLEN / WORDLEN]; //CHUNKLEN/WORDLEN=16
        for (uint64_t i = 0; i < num_chunk; i++) {
            for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
                tmp[j] = input_data[j + i * CHUNKLEN / WORDLEN];
            }
            chunk_compress(dig, tmp);
        }
        delete[] tmp;
    } else
        error("wrong padding length!\n");
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

void SHA_256::digest(Integer* res, Integer input) {
    vector<Integer> input_data;
    padding(input_data, input);
    update(res, input_data);
}
