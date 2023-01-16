#ifndef _IZK_H_
#define _IZK_H_
#include "emp-tool/emp-tool.h"
#include "cipher/hmac_sha256.h"
#include "cipher/aead.h"
#include "cipher/prf.h"
#include "add.h"
#include "e2f.h"

template <typename IO>
class IZK {
   public:
    IO* io;
    BIGNUM* q;
    BN_CTX* ctx;

    IZK(IO* io, EC_GROUP* group) : io(io) {
        ctx = BN_CTX_new();
        this->group = group;
        q = BN_new();
        EC_GROUP_get_curve(group, q, NULL, NULL, ctx);
    }
    ~IZK() {
        BN_CTX_free(ctx);
        BN_free(q);
    }

    inline void prove_master_and_expansion_keys(Integer& ms,
                                           Integer& key,
                                           const BIGNUM* pms_a,
                                           const BIGNUM* pms_b,
                                           const unsigned char* rc,
                                           size_t rc_len,
                                           const unsigned char* rs,
                                           size_t rs_len,
                                           int party) {
        size_t len = BN_num_bytes(pms_a);
        assert(len == BN_num_bytes(pms_b));

        unsigned char* bufa = new unsigned char[len];
        unsigned char* bufb = new unsigned char[len];
        BN_bn2bin(pms_a, bufa);
        reverse(bufa, bufa + len);

        BN_bn2bin(pms_b, bufb);
        reverse(bufb, bufb + len);

        Integer pmsa, pmsb;
        pmsa = Integer(len * 8, bufa, PUBLIC);
        pmsb = Integer(len * 8, bufb, ALICE);

        Integer pmsbits;
        addmod(pmsbits, pmsa, pmsb, q);

        delete[] bufa;
        delete[] bufb;
    }
};
#endif