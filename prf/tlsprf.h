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

    void phash(Integer& res, size_t bitlen, const Integer secret, const Integer seed) {
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

    inline void prf(Integer& res, size_t bitlen, const Integer secret, const Integer label, const Integer seed) {
        Integer label_seed;
        concat(label_seed, &label, 1);
        concat(label_seed, &seed, 1);
        phash(res, bitlen, secret, label_seed);
    }

    inline size_t hmac_calls() { return hmac_calls_num; }
};

#endif