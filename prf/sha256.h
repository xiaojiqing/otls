#ifndef SHA256_H
#define SHA256_H

#include "emp-tool/emp-tool.h"
#include "utils.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace emp;
using std::vector;

class SHA_256 {
   public:
    static const int DIGLEN = 8;
    static const int VALLEN = 8;
    static const int WORDLEN = 32;
    static const int KLEN = 64;
    static const int CHUNKLEN = 512;

    int compression_calls_num = 0;
    bool in_open_flag = false;
    bool out_open_flag = false;
    uint32_t in_dig[DIGLEN];
    Integer out_dig[DIGLEN];

    const Integer sha256_h[VALLEN] = {Integer(WORDLEN, 0x6a09e667UL, PUBLIC), Integer(WORDLEN, 0xbb67ae85UL, PUBLIC), Integer(WORDLEN, 0x3c6ef372UL, PUBLIC), Integer(WORDLEN, 0xa54ff53aUL, PUBLIC),
                                      Integer(WORDLEN, 0x510e527fUL, PUBLIC), Integer(WORDLEN, 0x9b05688cUL, PUBLIC), Integer(WORDLEN, 0x1f83d9abUL, PUBLIC), Integer(WORDLEN, 0x5be0cd19UL, PUBLIC)};

    const Integer sha256_k[KLEN] = {
      Integer(WORDLEN, 0x428a2f98UL, PUBLIC), Integer(WORDLEN, 0x71374491UL, PUBLIC), Integer(WORDLEN, 0xb5c0fbcfUL, PUBLIC), Integer(WORDLEN, 0xe9b5dba5UL, PUBLIC), Integer(WORDLEN, 0x3956c25bUL, PUBLIC), Integer(WORDLEN, 0x59f111f1UL, PUBLIC),
      Integer(WORDLEN, 0x923f82a4UL, PUBLIC), Integer(WORDLEN, 0xab1c5ed5UL, PUBLIC), Integer(WORDLEN, 0xd807aa98UL, PUBLIC), Integer(WORDLEN, 0x12835b01UL, PUBLIC), Integer(WORDLEN, 0x243185beUL, PUBLIC), Integer(WORDLEN, 0x550c7dc3UL, PUBLIC),
      Integer(WORDLEN, 0x72be5d74UL, PUBLIC), Integer(WORDLEN, 0x80deb1feUL, PUBLIC), Integer(WORDLEN, 0x9bdc06a7UL, PUBLIC), Integer(WORDLEN, 0xc19bf174UL, PUBLIC), Integer(WORDLEN, 0xe49b69c1UL, PUBLIC), Integer(WORDLEN, 0xefbe4786UL, PUBLIC),
      Integer(WORDLEN, 0x0fc19dc6UL, PUBLIC), Integer(WORDLEN, 0x240ca1ccUL, PUBLIC), Integer(WORDLEN, 0x2de92c6fUL, PUBLIC), Integer(WORDLEN, 0x4a7484aaUL, PUBLIC), Integer(WORDLEN, 0x5cb0a9dcUL, PUBLIC), Integer(WORDLEN, 0x76f988daUL, PUBLIC),
      Integer(WORDLEN, 0x983e5152UL, PUBLIC), Integer(WORDLEN, 0xa831c66dUL, PUBLIC), Integer(WORDLEN, 0xb00327c8UL, PUBLIC), Integer(WORDLEN, 0xbf597fc7UL, PUBLIC), Integer(WORDLEN, 0xc6e00bf3UL, PUBLIC), Integer(WORDLEN, 0xd5a79147UL, PUBLIC),
      Integer(WORDLEN, 0x06ca6351UL, PUBLIC), Integer(WORDLEN, 0x14292967UL, PUBLIC), Integer(WORDLEN, 0x27b70a85UL, PUBLIC), Integer(WORDLEN, 0x2e1b2138UL, PUBLIC), Integer(WORDLEN, 0x4d2c6dfcUL, PUBLIC), Integer(WORDLEN, 0x53380d13UL, PUBLIC),
      Integer(WORDLEN, 0x650a7354UL, PUBLIC), Integer(WORDLEN, 0x766a0abbUL, PUBLIC), Integer(WORDLEN, 0x81c2c92eUL, PUBLIC), Integer(WORDLEN, 0x92722c85UL, PUBLIC), Integer(WORDLEN, 0xa2bfe8a1UL, PUBLIC), Integer(WORDLEN, 0xa81a664bUL, PUBLIC),
      Integer(WORDLEN, 0xc24b8b70UL, PUBLIC), Integer(WORDLEN, 0xc76c51a3UL, PUBLIC), Integer(WORDLEN, 0xd192e819UL, PUBLIC), Integer(WORDLEN, 0xd6990624UL, PUBLIC), Integer(WORDLEN, 0xf40e3585UL, PUBLIC), Integer(WORDLEN, 0x106aa070UL, PUBLIC),
      Integer(WORDLEN, 0x19a4c116UL, PUBLIC), Integer(WORDLEN, 0x1e376c08UL, PUBLIC), Integer(WORDLEN, 0x2748774cUL, PUBLIC), Integer(WORDLEN, 0x34b0bcb5UL, PUBLIC), Integer(WORDLEN, 0x391c0cb3UL, PUBLIC), Integer(WORDLEN, 0x4ed8aa4aUL, PUBLIC),
      Integer(WORDLEN, 0x5b9cca4fUL, PUBLIC), Integer(WORDLEN, 0x682e6ff3UL, PUBLIC), Integer(WORDLEN, 0x748f82eeUL, PUBLIC), Integer(WORDLEN, 0x78a5636fUL, PUBLIC), Integer(WORDLEN, 0x84c87814UL, PUBLIC), Integer(WORDLEN, 0x8cc70208UL, PUBLIC),
      Integer(WORDLEN, 0x90befffaUL, PUBLIC), Integer(WORDLEN, 0xa4506cebUL, PUBLIC), Integer(WORDLEN, 0xbef9a3f7UL, PUBLIC), Integer(WORDLEN, 0xc67178f2UL, PUBLIC)};

    const uint32_t plain_sha256_k[KLEN] = {0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL,
                                           0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL, 0xa831c66dUL,
                                           0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL,
                                           0x92722c85UL, 0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
                                           0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};

    SHA_256(){};
    ~SHA_256(){};

    inline void padding(Integer& padded_input, const Integer input) {
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

    void update(Integer* dig, const Integer padded_input, bool out_flag = false) {
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
            for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
                tmp_block[j] = input_data[j];
            }

            if (out_flag == true) {
                if (out_open_flag == false) {
                    chunk_compress(dig, tmp_block);

                    for (int i = 0; i < DIGLEN; i++)
                        out_dig[i] = dig[i];
                    out_open_flag = true;
                } else {
                    for (int i = 0; i < DIGLEN; i++)
                        dig[i] = out_dig[i];
                }
            } else {
                chunk_compress(dig, tmp_block);
            }

            for (uint64_t i = 1; i < num_chunk; i++) {
                for (int j = 0; j < CHUNKLEN / WORDLEN; j++) {
                    tmp_block[j] = input_data[j + i * CHUNKLEN / WORDLEN];
                }
                chunk_compress(dig, tmp_block);
            }
            delete[] tmp_block;
        } else
            error("wrong padding length!\n");
    }

    void opt_update(uint32_t* plain_dig, const Integer sec_input, unsigned char* pub_input, size_t pub_len, bool in_flag = false) {
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

            if (in_flag == true) {
                if (in_open_flag == false) {
                    Integer* dig = new Integer[VALLEN];
                    for (int i = 0; i < VALLEN; i++)
                        dig[i] = sha256_h[i];
                    chunk_compress(dig, input_data.data());
                    Integer tmpInt;
                    for (int i = 0; i < VALLEN; ++i)
                        tmpInt.bits.insert(tmpInt.bits.end(), std::begin(dig[i].bits), std::end(dig[i].bits));
                    tmpInt.reveal<uint32_t>((uint32_t*)plain_dig, PUBLIC);

                    delete[] dig;
                    for (int i = 0; i < DIGLEN; i++)
                        in_dig[i] = plain_dig[i];

                    in_open_flag = true;
                } else {
                    for (int i = 0; i < DIGLEN; i++) {
                        plain_dig[i] = in_dig[i];
                    }
                }
            } else {
                Integer* dig = new Integer[VALLEN];
                for (int i = 0; i < VALLEN; i++)
                    dig[i] = sha256_h[i];

                chunk_compress(dig, input_data.data());
                Integer tmpInt;
                for (int i = 0; i < VALLEN; ++i)
                    tmpInt.bits.insert(tmpInt.bits.end(), std::begin(dig[i].bits), std::end(dig[i].bits));
                tmpInt.reveal<uint32_t>((uint32_t*)plain_dig, PUBLIC);

                delete[] dig;
            }

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

    void chunk_compress(Integer* input_h, Integer* chunk) {
        compression_calls_num++;
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

    void opt_chunk_compress(uint32_t* input_h, unsigned char* chunk) {
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

    inline void digest(Integer* res, Integer input, bool out_flag = false) {
        Integer padded_input;
        padding(padded_input, input);
        update(res, padded_input, out_flag);
    }

    inline void opt_digest(uint32_t* res, const Integer sec_input, unsigned char* pub_input, size_t pub_len, bool in_flag = false) { opt_update(res, sec_input, pub_input, pub_len, in_flag); }

    inline size_t compression_calls() { return compression_calls_num; }
};

#endif
