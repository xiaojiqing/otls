#ifndef _AES_GCM_H_
#define _AES_GCM_H_
#include "emp-tool/emp-tool.h"
#include "utils.h"
using namespace emp;

static block R = makeBlock(0xe100000000000000, 0x00);
static string circuit_file_location =
  macro_xstr(EMP_CIRCUIT_PATH) + string("bristol_fashion/");
static BristolFashion aes = BristolFashion((circuit_file_location + "aes_128.txt").c_str());

// inline block rsht(block x, size_t i) {
//     uint64_t* data = (uint64_t*)&x;
//     if (i == 0) {
//         return x;
//     } else if (i < 64) {
//         return makeBlock((data[1] >> i), (data[1] << (64 - i)) ^ (data[0] >> i));
//     } else if (i < 128) {
//         return makeBlock(0x00, data[1] >> (i - 64));
//     } else
//         return makeBlock(0x00, 0x00);
// }

// inline block mulBlock(block x, block y) {
//     block Z = zero_block, V = y;

//     for (int i = 0; i < 128; i++) {
//         Z = getLSB(rsht(x, 127 - i)) ? Z ^ V : Z;
//         V = getLSB(V) ? rsht(V, 1) ^ R : rsht(V, 1);
//     }
//     return Z;
// }

inline block mulBlock(block a, block b) {
    __m128i tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);

    tmp7 = _mm_srli_epi32(tmp3, 31);
    tmp8 = _mm_srli_epi32(tmp6, 31);
    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);

    tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);

    tmp7 = _mm_slli_epi32(tmp3, 31);
    tmp8 = _mm_slli_epi32(tmp3, 30);
    tmp9 = _mm_slli_epi32(tmp3, 25);
    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);
    tmp8 = _mm_srli_si128(tmp7, 4);
    tmp7 = _mm_slli_si128(tmp7, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp7);

    tmp2 = _mm_srli_epi32(tmp3, 1);
    tmp4 = _mm_srli_epi32(tmp3, 2);
    tmp5 = _mm_srli_epi32(tmp3, 7);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp8);
    tmp3 = _mm_xor_si128(tmp3, tmp2);
    return _mm_xor_si128(tmp6, tmp3);
}

inline block ghash(block h, block* x, size_t m) {
    block y = zero_block;
    for (int i = 0; i < m; i++) {
        y = mulBlock((y ^ x[i]), h);
    }
    return y;
}
class AESGCM {
   public:
    Integer key;
    Integer H = Integer(128, 0, PUBLIC);
    Integer nonce;
    AESGCM(Integer& key, unsigned char* iv, size_t iv_len) : key(key) {
        if (iv_len != 12) {
            error("invalid IV length!\n");
        }
        reverse(iv, iv + iv_len);
        nonce = Integer(96, iv, PUBLIC);
        Integer ONE = Integer(32, 1, PUBLIC);
        concat(nonce, &ONE, 1);

        computeH();
    }
    ~AESGCM() {}

    //AESGCM(Integer _key) : key(_key) { computeH(); }
    // inline void init(Integer& key) {
    //     this->key = key;
    //     computeH();
    // }
    inline void computeH() {
        Integer in(128, 0, PUBLIC);
        concat(in, &key, 1);
        aes.compute(H.bits.data(), in.bits.data());
    }

    inline Integer inc(Integer& counter, size_t s) {
        if (counter.size() < s) {
            error("invalid length s!");
        }
        Integer msb = counter, lsb = counter;
        msb.bits.erase(msb.bits.begin(), msb.bits.begin() + s);
        lsb.bits.erase(lsb.bits.begin() + s, lsb.bits.end());
        lsb = lsb + Integer(s, 1, PUBLIC);

        concat(msb, &lsb, 1);
        return msb;
    }

    inline void gctr(Integer& res, size_t m) {
        Integer tmp(128, 0, PUBLIC);
        for (int i = 0; i < m; i++) {
            Integer content = nonce;
            concat(content, &key, 1);
            aes.compute(tmp.bits.data(), content.bits.data());

            concat(res, &tmp, 1);
            nonce = inc(nonce, 32);
        }
    }

    void enc_finished_msg(NetIO* io,
                          unsigned char* ctxt,
                          unsigned char* tag,
                          const unsigned char* msg,
                          size_t msg_len,
                          const unsigned char* aad,
                          size_t aad_len,
                          int party) {
        // u = 128 * ceil(msg_len/128) - 8*msg_len
        size_t u = 128 * ((msg_len * 8 + 128 - 1) / 128) - msg_len * 8;

        size_t ctr_len = (msg_len * 8 + 128 - 1) / 128;

        Integer Z;
        gctr(Z, 1 + ctr_len);

        H.bits.insert(H.bits.end(), Z.bits.end() - 128, Z.bits.end());

        block* h_z0 = new block[2];
        H.reveal<block>((block*)h_z0, ALICE);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        unsigned char* z = new unsigned char[msg_len];
        Z.reveal<unsigned char>((unsigned char*)z, BOB);
        reverse(z, z + msg_len);
        if (party == ALICE) {
            // v = 128 * ceil(8*aad_len/128) - aad_len*8
            size_t v = 128 * ((aad_len * 8 + 128 - 1) / 128) - aad_len * 8;

            if (msg_len != 0) {
                io->recv_data(ctxt, msg_len);
            }

            size_t len = u / 8 + msg_len + v / 8 + aad_len + 16;

            unsigned char* x = new unsigned char[len];

            unsigned char ilen[8], mlen[8];
            for (int i = 0; i < 8; i++) {
                ilen[i] = (8 * aad_len) >> (7 - i) * 8;
                mlen[i] = (8 * msg_len) >> (7 - i) * 8;
            }

            memcpy(x, aad, aad_len);
            memset(x + aad_len, 0, v / 8);
            memcpy(x + aad_len + v / 8, ctxt, msg_len);
            memset(x + aad_len + v / 8 + msg_len, 0, u / 8);
            memcpy(x + aad_len + v / 8 + msg_len + u / 8, ilen, 8);
            memcpy(x + aad_len + v / 8 + msg_len + u / 8 + 8, mlen, 8);

            reverse(x, x + len);
            block* xblk = (block*)x;
            reverse(xblk, xblk + (8 * len) / 128);

            block t = ghash(h_z0[0], xblk, 8 * len / 128);
            t = t ^ h_z0[1];

            memcpy(tag, (unsigned char*)&t, 16);
            reverse(tag, tag + 16);
            io->send_data(tag, 16);
            // io->flush();

            delete[] x;
        } else if (party == BOB) {
            for (int i = 0; i < msg_len; i++) {
                ctxt[i] = z[i] ^ msg[i];
            }
            if (msg_len != 0) {
                io->send_data(ctxt, msg_len);
                // io->flush();
            }
            io->recv_data(tag, 16);
        }

        delete[] h_z0;
        delete[] z;
    }

    bool dec_finished_msg(NetIO* io,
                          unsigned char* msg,
                          const unsigned char* ctxt,
                          size_t ctxt_len,
                          const unsigned char* tag,
                          const unsigned char* aad,
                          size_t aad_len,
                          int party) {
        // u = 128 * ceil(ctxt_len/128) - 8*ctxt_len
        size_t u = 128 * ((ctxt_len * 8 + 128 - 1) / 128) - ctxt_len * 8;

        size_t ctr_len = (ctxt_len * 8 + 128 - 1) / 128;

        Integer Z;
        gctr(Z, 1 + ctr_len);

        H.bits.insert(H.bits.end(), Z.bits.end() - 128, Z.bits.end());

        block* h_z0 = new block[2];
        H.reveal<block>((block*)h_z0, ALICE);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        unsigned char* z = new unsigned char[ctxt_len];
        Z.reveal<unsigned char>((unsigned char*)z, BOB);
        reverse(z, z + ctxt_len);

        bool res = false;

        if (party == ALICE) {
            // v = 128 * ceil(8*aad_len/128) - aad_len*8
            size_t v = 128 * ((aad_len * 8 + 128 - 1) / 128) - aad_len * 8;

            size_t len = u / 8 + ctxt_len + v / 8 + aad_len + 16;

            unsigned char* x = new unsigned char[len];

            unsigned char ilen[8], mlen[8];
            for (int i = 0; i < 8; i++) {
                ilen[i] = (8 * aad_len) >> (7 - i) * 8;
                mlen[i] = (8 * ctxt_len) >> (7 - i) * 8;
            }

            memcpy(x, aad, aad_len);
            memset(x + aad_len, 0, v / 8);
            memcpy(x + aad_len + v / 8, ctxt, ctxt_len);
            memset(x + aad_len + v / 8 + ctxt_len, 0, u / 8);
            memcpy(x + aad_len + v / 8 + ctxt_len + u / 8, ilen, 8);
            memcpy(x + aad_len + v / 8 + ctxt_len + u / 8 + 8, mlen, 8);

            reverse(x, x + len);
            block* xblk = (block*)x;
            reverse(xblk, xblk + (8 * len) / 128);

            block t = ghash(h_z0[0], xblk, 8 * len / 128);
            t = t ^ h_z0[1];

            unsigned char* tagc = (unsigned char*)&t;
            reverse(tagc, tagc + 16);

            res = (memcmp(tag, tagc, 16) == 0);
            io->send_bool(&res, 1);
            // io->flush();

            delete[] x;
        } else if (party == BOB) {
            res = false;
            io->recv_bool(&res, 1);
            if (res) {
                for (int i = 0; i < ctxt_len; i++) {
                    msg[i] = ctxt[i] ^ z[i];
                }
            }
        }

        delete[] h_z0;
        delete[] z;
        return res;
    }
};
#endif