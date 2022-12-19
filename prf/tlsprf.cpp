#include "emp-tool/emp-tool.h"
#include "utils.h"
#include "tlsprf.h"

using namespace emp;

void TLSPrf::phash(Integer& res, size_t bitlen, const Integer secret, const Integer seed) {
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

void TLSPrf::prf(Integer& res, size_t bitlen, const Integer secret, const Integer label, const Integer seed) {
    Integer label_seed;
    concat(label_seed, &label, 1);
    concat(label_seed, &seed, 1);
    phash(res, bitlen, secret, label_seed);
}