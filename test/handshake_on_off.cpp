#include "protocol/handshake.h"
#include "backend/backend.h"
#include <iostream>
#include "backend/bn_utils.h"

using namespace std;
using namespace emp;

void handshake_test_offline() {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    unsigned char* rc = new unsigned char[32];
    unsigned char* rs = new unsigned char[32];

    // unsigned char* ufinc = new unsigned char[finished_msg_length];
    // unsigned char* ufins = new unsigned char[finished_msg_length];

    unsigned char* tau_c = new unsigned char[32];
    unsigned char* tau_s = new unsigned char[32];

    //unsigned char* iv_oct = new unsigned char[24];

    memset(rc, 0x11, 32);
    memset(rs, 0x22, 32);
    memset(tau_c, 0x33, 32);
    memset(tau_s, 0x44, 32);

    // unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
    //                        0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    // size_t aad_len = sizeof(aad);

    HandShakeOffline* hs_offline = new HandShakeOffline(group);
    hs_offline->compute_extended_master_key(rc, 32);
    hs_offline->compute_expansion_keys(rc, 32, rs, 32);
    hs_offline->compute_client_finished_msg(client_finished_label,
                                            client_finished_label_length, tau_c, 32);
    hs_offline->compute_server_finished_msg(server_finished_label,
                                            server_finished_label_length, tau_s, 32);

    AEADOffline* aead_c_offline = new AEADOffline(hs_offline->client_write_key);
    AEADOffline* aead_s_offline = new AEADOffline(hs_offline->server_write_key);

    AEADOffline* aead_c_offline_server = new AEADOffline(hs_offline->client_write_key);
    AEADOffline* aead_s_offline_server = new AEADOffline(hs_offline->server_write_key);

    hs_offline->encrypt_client_finished_msg(aead_c_offline, 12);
    aead_c_offline_server->decrypt(12);

    aead_s_offline_server->encrypt(12);

    hs_offline->decrypt_server_finished_msg(aead_s_offline, 12);

    delete hs_offline;
    delete aead_c_offline;
    delete aead_s_offline;
}
template <typename IO>
void handshake_test(IO* io, COT<IO>* cot, int party) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    HandShake<NetIO>* hs = new HandShake<NetIO>(io, cot, group);

    EC_POINT* V = EC_POINT_new(group);
    EC_POINT* Tc = EC_POINT_new(group);
    BIGNUM* t = BN_new();

    BIGNUM* ts = BN_new();
    EC_POINT* Ts = EC_POINT_new(hs->group);
    BN_set_word(ts, 2);
    EC_POINT_mul(hs->group, Ts, ts, NULL, NULL, hs->ctx);

    unsigned char* rc = new unsigned char[32];
    unsigned char* rs = new unsigned char[32];

    unsigned char* ufinc = new unsigned char[finished_msg_length];
    unsigned char* ufins = new unsigned char[finished_msg_length];

    unsigned char* tau_c = new unsigned char[32];
    unsigned char* tau_s = new unsigned char[32];

    //unsigned char* iv_oct = new unsigned char[24];

    memset(rc, 0x11, 32);
    memset(rs, 0x22, 32);
    memset(tau_c, 0x33, 32);
    memset(tau_s, 0x44, 32);

    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    size_t aad_len = sizeof(aad);

    if (party == BOB) {
        hs->compute_pado_VA(V, Ts);
    } else {
        hs->compute_client_VB(Tc, V, Ts);
    }

    hs->compute_pms_offline(party);

    BIGNUM* pms = BN_new();
    BIGNUM* full_pms = BN_new();
    hs->compute_pms_online(pms, V, party);

    //hs->compute_master_key(pms, rc, 32, rs, 32);
    hs->compute_extended_master_key(pms, rc, 32);

    hs->compute_expansion_keys(rc, 32, rs, 32);

    hs->compute_client_finished_msg(client_finished_label, client_finished_label_length, tau_c,
                                    32);
    hs->compute_server_finished_msg(server_finished_label, server_finished_label_length, tau_s,
                                    32);
    unsigned char iv_c[12], iv_s[12];
    memcpy(iv_c, hs->client_write_iv, iv_length);
    memset(iv_c + iv_length, 0x11, 8);
    memcpy(iv_s, hs->server_write_iv, iv_length);
    memset(iv_s + iv_length, 0x22, 8);
    AEAD<NetIO>* aead_c = new AEAD<NetIO>(io, cot, hs->client_write_key);
    AEAD<NetIO>* aead_s = new AEAD<NetIO>(io, cot, hs->server_write_key);

    // These AEAD instances simulate the server side.
    AEAD<NetIO>* aead_c_server = new AEAD<NetIO>(io, cot, hs->client_write_key);

    AEAD<NetIO>* aead_s_server = new AEAD<NetIO>(io, cot, hs->server_write_key);

    unsigned char* ctxt = new unsigned char[finished_msg_length];
    unsigned char* tag = new unsigned char[tag_length];
    unsigned char* msg = new unsigned char[finished_msg_length];

    hs->encrypt_client_finished_msg(aead_c, ctxt, tag, hs->client_ufin, 12, aad, aad_len, iv_c,
                                    12, party);
    bool res = aead_c_server->decrypt(io, msg, ctxt, finished_msg_length, tag, aad, aad_len,
                                      iv_c, 12, party);
    cout << "res: " << res << endl;
    for (int i = 0; i < finished_msg_length; i++)
        cout << hex << (int)msg[i];
    cout << endl;

    for (int i = 0; i < finished_msg_length; i++)
        cout << hex << (int)hs->client_ufin[i];
    cout << endl;

    unsigned char* ctxt2 = new unsigned char[finished_msg_length];
    unsigned char* tag2 = new unsigned char[tag_length];
    unsigned char* msg2 = new unsigned char[finished_msg_length];

    aead_s_server->encrypt(io, ctxt2, tag2, hs->server_ufin, finished_msg_length, aad, aad_len,
                           iv_s, 12, party);

    bool res2 = hs->decrypt_server_finished_msg(aead_s, msg2, ctxt2, finished_msg_length, tag2,
                                                aad, aad_len, iv_s, 12, party);
    cout << "res2: " << res2 << endl;

    // prove handshake
    if (party == BOB) {
        send_bn(io, hs->ta_pado);
    } else {
        recv_bn(io, t);
        EC_POINT* T = EC_POINT_new(hs->group);
        EC_POINT_mul(hs->group, T, t, NULL, NULL, hs->ctx);
        if (EC_POINT_cmp(hs->group, T, hs->Ta_client, hs->ctx)) {
            error("Ta is not consistent!\n");
        }

        BN_mod_add(t, t, hs->tb_client, EC_GROUP_get0_order(hs->group), hs->ctx);

        EC_POINT_mul(hs->group, T, NULL, Ts, t, hs->ctx);
        EC_POINT_get_affine_coordinates(hs->group, T, full_pms, NULL, hs->ctx);

        EC_POINT_free(T);
    }

    switch_to_zk();
    Integer ms, key_c, key_s;
    //hs->prove_master_key(ms, full_pms, rc, 32, rs, 32, party);
    hs->prove_extended_master_key(ms, full_pms, rc, 32, party);
    hs->prove_expansion_keys(key_c, key_s, ms, rc, 32, rs, 32, party);

    AEAD_Proof<IO>* aead_proof_c = new AEAD_Proof<IO>(aead_c, key_c, party);
    AEAD_Proof<IO>* aead_proof_s = new AEAD_Proof<IO>(aead_s, key_s, party);

    hs->prove_client_finished_msg(ms, client_finished_label, client_finished_label_length,
                                  tau_c, 32, party);
    hs->prove_server_finished_msg(ms, server_finished_label, server_finished_label_length,
                                  tau_s, 32, party);
    Integer client_z0, server_z0;
    hs->prove_enc_dec_finished_msg(aead_proof_c, client_z0, ctxt, finished_msg_length, iv_c,
                                   12);
    hs->prove_enc_dec_finished_msg(aead_proof_s, server_z0, ctxt2, finished_msg_length, iv_s,
                                   12);

    hs->handshake_check(party);

    sync_zk_gc<IO>();
    switch_to_gc();

    EC_POINT_free(V);
    EC_POINT_free(Tc);
    BN_free(t);
    BN_free(ts);
    BN_free(pms);
    BN_free(full_pms);
    EC_POINT_free(Ts);

    delete hs;
    delete[] rc;
    delete[] rs;
    delete[] ufinc;
    delete[] ufins;
    delete[] tau_c;
    delete[] tau_s;
    delete[] ctxt;
    delete[] ctxt2;
    delete[] tag2;
    delete[] msg2;
    delete[] tag;
    delete[] msg;
    // delete[] iv_oct;

    delete aead_c;
    delete aead_s;
    delete aead_c_server;
    delete aead_s_server;
    delete aead_proof_c;
    delete aead_proof_s;
    EC_GROUP_free(group);
}

const int threads = 1;
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    BoolIO<NetIO>* ios[threads];
    for (int i = 0; i < threads; i++)
        ios[i] = new BoolIO<NetIO>(io, party == ALICE);

    auto start = emp::clock_start();
    auto comm = io->counter;
    setup_protocol<NetIO>(io, ios, threads, party, true);
    cout << "setup time: " << dec << emp::time_from(start) << endl;
    cout << "setup comm: " << io->counter << endl;

    comm = io->counter;
    start = emp::clock_start();

    handshake_test_offline();
    switch_to_online<NetIO>(party);
    cout << "offline time: " << dec << emp::time_from(start) << endl;
    cout << "offline comm: " << io->counter - comm << endl;

    comm = io->counter;

    start = emp::clock_start();
    auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
    IKNP<NetIO>* cot = prot->ot;
    handshake_test<NetIO>(io, cot, party);
    cout << "online time: " << dec << emp::time_from(start) << endl;
    cout << "online comm: " << io->counter - comm << endl;
    finalize_protocol();

    bool cheat = CheatRecord::cheated();
    if (cheat)
        error("cheat!\n");
    delete io;
    for (int i = 0; i < threads; i++) {
        delete ios[i];
    }
    return 0;
}
