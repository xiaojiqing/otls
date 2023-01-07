#ifndef _HAND_SHAKE_H_
#define _HAND_SHAKE_H_
#include "emp-tool/emp-tool.h"
#include "add.h"
#include "e2f.h"
#include "cipher/hmac_sha256.h"
#include "cipher/aesgcm.h"
#include "cipher/prf.h"

using namespace emp;
using namespace std;

static unsigned char master_key_label[] = {"master key"};
static unsigned char key_expansion_label[] = {"key expansion"};
static unsigned char client_finished_label[] = {"client finished"};
static unsigned char server_finished_label[] = {"server finished"};

static size_t master_key_label_length = sizeof(master_key_label) - 1;
static size_t key_expansion_label_length = sizeof(key_expansion_label) - 1;
static size_t client_finished_label_length = sizeof(client_finished_label) - 1;
static size_t server_finished_label_length = sizeof(server_finished_label) - 1;

static size_t master_key_bit_length = 384;
static size_t expansion_key_bit_length = 320;
static size_t finished_msg_bit_length = 96;

template <typename IO>
class HandShake {
   public:
    IO* io;
    HMAC_SHA256 hmac;
    PRF prf;
    E2F<IO>* e2f = nullptr;
    EC_GROUP* group = nullptr;
    BIGNUM* q = nullptr;
    BN_CTX* ctx = nullptr;

    HandShake(IO* io, COT<IO>* ot, EC_GROUP* group) : io(io) {
        ctx = BN_CTX_new();
        EC_GROUP_copy(this->group, group);
        EC_GROUP_get_curve(this->group, this->q, NULL, NULL, ctx);
        e2f = new E2F<IO>(io, ot, q, BN_num_bits(q));
    }
    ~HandShake() {
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        BN_free(q);
        delete e2f;
    }

    inline void compute_pado_VA(EC_POINT* Va, BIGNUM* t, const EC_POINT* Ts) {
        BN_rand(t, BN_num_bytes(q) * 8, 0, 0);
        BN_mod(t, t, q, ctx);

        EC_POINT* Ta = EC_POINT_new(group);
        if (!EC_POINT_mul(group, Ta, t, NULL, NULL, ctx))
            error("error in computing TA!\n");

        unsigned char buf[64];
        // Should compress the point.
        int size = EC_POINT_point2oct(group, Ta, POINT_CONVERSION_UNCOMPRESSED, buf, 64, ctx);
        io->send_data(buf, size);

        if (!EC_POINT_mul(group, Va, NULL, Ts, t, ctx))
            error("error in computing VA!\n");

        EC_POINT_free(Ta);
    }

    inline void compute_client_VB(EC_POINT* Tc, EC_POINT* Vb, BIGNUM* t, const EC_POINT* Ts) {
        BN_rand(t, BN_num_bytes(q) * 8, 0, 0);
        BN_mod(t, t, q, ctx);

        EC_POINT* Tb = EC_POINT_new(group);
        if (!EC_POINT_mul(group, Tb, t, NULL, NULL, ctx))
            error("error in computing TB!\n");

        EC_POINT* Ta = EC_POINT_new(group);
        unsigned char buf[64];
        io->recv_data(buf, 64);
        if (!EC_POINT_oct2point(group, Ta, buf, 64, ctx))
            error("error in converting oct to TA\n");

        if (!EC_POINT_mul(group, Vb, NULL, Ts, t, ctx))
            error("error in computing VB!\n");
        EC_POINT_add(group, Tc, Ta, Tb, ctx);

        EC_POINT_free(Tb);
        EC_POINT_free(Ta);
    }

    inline void compute_pms_offline(int party) { e2f->compute_offline(party); }

    inline void compute_pms_online(BIGNUM* pms, const EC_POINT* V, int party) {
        BIGNUM* x = BN_new();
        BIGNUM* y = BN_new();

        EC_POINT_get_affine_coordinates(group, V, x, y, ctx);
        e2f->compute_online(pms, x, y, party);

        BN_free(x);
        BN_free(y);
    }

    inline void compute_master_and_expansion_keys(Integer& ms,
                                                  Integer& key,
                                                  const BIGNUM* pms,
                                                  unsigned char* rc,
                                                  size_t rc_len,
                                                  unsigned char* rs,
                                                  size_t rs_len,
                                                  int party) {
        size_t len = BN_num_bytes(pms);
        unsigned char* buf = new unsigned char[len];
        BN_bn2bin(pms, buf);
        reverse(buf, buf + len);
        Integer pmsa, pmsb;

        if (party == ALICE) {
            Integer pmsa(len * 8, buf, ALICE);
            Integer pmsb(len * 8, 0, BOB);
        } else {
            Integer pmsa(len * 8, 0, ALICE);
            Integer pmsb(len * 8, buf, BOB);
        }

        Integer pmsbits;
        addmod(pmsbits, pmsa, pmsb, q);

        size_t seed_len = rc_len + rs_len;
        unsigned char* seed = new unsigned char[seed_len];
        memcpy(seed, rc, rc_len);
        memcpy(seed + rc_len, rs, rs_len);

        hmac.init(pmsbits);
        prf.opt_compute(hmac, ms, master_key_bit_length, pmsbits, master_key_label,
                        master_key_label_length, seed, seed_len, true, true);

        memcpy(seed, rs, rs_len);
        memcpy(seed + rs_len, rc, rc_len);

        hmac.init(ms);
        prf.opt_compute(hmac, key, expansion_key_bit_length, ms, key_expansion_label,
                        key_expansion_label_length, seed, seed_len, true, true);

        delete[] buf;
        delete[] seed;
    }

    inline void compute_client_finished_message(Integer& out,
                                                const Integer& ms,
                                                unsigned char* tauc,
                                                size_t tauc_len) {
        prf.opt_compute(hmac, out, finished_msg_bit_length, ms, client_finished_label,
                        client_finished_label_length, tauc, tauc_len, true, true);
    }

    inline void encrypt_client_finished_message(AESGCM& aesgcm_c,
                                                unsigned char* ctxt,
                                                unsigned char* tag,
                                                const unsigned char* msg,
                                                size_t msg_len,
                                                const unsigned char* aad,
                                                size_t aad_len,
                                                int party) {
        aesgcm_c.enc_finished_msg(io, ctxt, tag, msg, msg_len, aad, aad_len, party);
    }

    inline void compute_server_finished_message(Integer& out,
                                                const Integer& ms,
                                                unsigned char* taus,
                                                size_t taus_len) {
        prf.opt_compute(hmac, out, finished_msg_bit_length, ms, server_finished_label,
                        server_finished_label_length, taus, taus_len, true, true);
    }

    inline bool decrypted_server_finished_message(AESGCM& aesgcm_s,
                                                  unsigned char* msg,
                                                  const unsigned char* ctxt,
                                                  size_t ctxt_len,
                                                  const unsigned char* tag,
                                                  const unsigned char* aad,
                                                  size_t aad_len,
                                                  int party) {
        return aesgcm_s.dec_finished_msg(io, msg, ctx, ctxt_len, tag, aad, aad_len, party);
    }

    inline bool check_server_finished_message() {}

    inline void compute_offline() {}
    inline void compute_online() {}
};

#endif