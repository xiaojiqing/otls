#ifndef _TLSPRF_H_
#define _TLSPRF_H_

#include "emp-tool/emp-tool.h"
#include "hmac_sha256.h"
#include "utils.h"

using namespace emp;

class TLSPrf : public HMAC_SHA_256 {
   public:
    TLSPrf(){};
    ~TLSPrf(){};
    size_t hmac_calls_num = 0;

    inline void phash(Integer& res, size_t bitlen, const Integer secret, const Integer seed) {
        size_t blks = bitlen / (DIGLEN * WORDLEN) + 1;
        Integer* A = new Integer[blks + 1];
        Integer* res_tmp = new Integer[blks];
        Integer* tmp = new Integer[DIGLEN];

        A[0] = seed;
        for (int i = 1; i < blks + 1; i++) {
            hmac_sha_256(tmp, secret, A[i - 1]);
            hmac_calls_num++;
            concat(A[i], tmp, DIGLEN);

            Integer As;
            concat(As, &A[i], 1);
            concat(As, &seed, 1);

            hmac_sha_256(tmp, secret, As);
            hmac_calls_num++;
            concat(res_tmp[i - 1], tmp, DIGLEN);
        }

        concat(res, res_tmp, blks);
        res.bits.erase(res.bits.begin(), res.bits.begin() + blks * (DIGLEN * WORDLEN) - bitlen);

        delete[] A;
        delete[] tmp;
        delete[] res_tmp;
    }

    inline void opt_phash(Integer& res, size_t bitlen, const Integer secret, const unsigned char* seed, size_t seedlen) {
        size_t blks = bitlen / (DIGLEN * WORDLEN) + 1;
        vector<unsigned char*> A;
        vector<size_t> hashlen;
        A.resize(blks + 1);
        A[0] = new unsigned char[seedlen];
        memcpy(A[0], seed, seedlen);
        hashlen.push_back(seedlen);

        Integer* tmp = new Integer[DIGLEN];
        Integer* res_tmp = new Integer[blks];

        unsigned char* As = new unsigned char[32 + seedlen];

        for (int i = 1; i < blks + 1; i++) {
            opt_hmac_sha_256(tmp, secret, A[i - 1], hashlen[i - 1]);
            hmac_calls_num++;
            A[i] = new unsigned char[32];
				//Xiao: Note that this will incur DIGLEN roundtrips
            for (int j = 0, k = 0; j < DIGLEN; j++, k += 4) {
                uint32_t tmpd = tmp[j].reveal<uint32_t>(PUBLIC);
                A[i][k] = (tmpd >> 24);
                A[i][k + 1] = (tmpd >> 16);
                A[i][k + 2] = (tmpd >> 8);
                A[i][k + 3] = tmpd;
            }
            hashlen.push_back(32);

            memcpy(As, A[i], 32);
            memcpy(As + 32, seed, seedlen);

            opt_hmac_sha_256(tmp, secret, As, 32 + seedlen);
            hmac_calls_num++;
            concat(res_tmp[i - 1], tmp, DIGLEN);
        }

        concat(res, res_tmp, blks);
        res.bits.erase(res.bits.begin(), res.bits.begin() + blks * (DIGLEN * WORDLEN) - bitlen);

        for (int i = 0; i < blks + 1; i++) {
            delete[] A[i];
        }

        delete[] As;
        delete[] tmp;
        delete[] res_tmp;
    }

    inline void prf(Integer& res, size_t bitlen, const Integer secret, const Integer label, const Integer seed) {
        Integer label_seed;
        concat(label_seed, &label, 1);
        concat(label_seed, &seed, 1);
        phash(res, bitlen, secret, label_seed);
    }

    inline void opt_prf(Integer& res, size_t bitlen, const Integer secret, const unsigned char* label, size_t labellen, const unsigned char* seed, size_t seedlen) {
        unsigned char* label_seed = new unsigned char[labellen + seedlen];
        memcpy(label_seed, label, labellen);
        memcpy(label_seed + labellen, seed, seedlen);
        opt_phash(res, bitlen, secret, label_seed, labellen + seedlen);

        delete[] label_seed;
    }

    inline size_t hmac_calls() { return hmac_calls_num; }
};

#endif