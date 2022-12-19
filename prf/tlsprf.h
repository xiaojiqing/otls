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
    void phash(Integer& res, size_t bitlen, const Integer secret, const Integer seed);

    void prf(Integer& res, size_t bitlen, const Integer secret, const Integer label, const Integer seed);

    inline size_t hmac_calls() { return hmac_calls_num; }
};

#endif