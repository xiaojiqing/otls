#include "emp-tool/emp-tool.h"
#include "backend/backend.h"
#include "prf/aesgcm.h"
#include <iostream>

using namespace emp;
using namespace std;

void mul_test() {
    block H = makeBlock(0x0388DACE60B6A392, 0xF328C2B971B2FE78);
    block C = makeBlock(0x66E94BD4EF8A2C3B, 0x884CFA59CA342B2E);
    block HC = makeBlock(0x5E2EC74691706288, 0x2C85B0685353DEB7);

    block HC1 = mulBlock(H, C);
    block HC2 = mulBlock(C, H);
    cout << "HC1: " << HC1 << endl;
    cout << "HC2: " << HC2 << endl;
    cout << "expected HC: " << HC << endl;

    block res = zero_block;
    gfmul(H, C, &res);
    cout << res << endl;
    gfmul(C, H, &res);
    cout << res << endl;

    block a = makeBlock(0x7b5b546573745665, 0x63746f725d53475d);
    block b = makeBlock(0x4869285368617929, 0x5b477565726f6e5d);
    gfmul(a, b, &res);
    cout << res << endl;
    gfmul(b, a, &res);
    cout << res << endl;
    block c = makeBlock(0x6d02da056a66d4cd, 0x035206a56a54d4a9);
    block d = makeBlock(0x860f0c1fa9ff53ff, 0xc0db81b7b2fd65fb);
    gfmul(c, d, &res);
    cout << res << endl;
    cout << mulBlock(a, b) << endl;
}

void aes_test() {
    unsigned char keyc[] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    reverse(keyc, keyc + 16);
    Integer key(128, keyc, ALICE);
    cout << key.reveal<string>() << endl;

    Integer c(128, 0, PUBLIC);
    concat(c, &key, 1);

    Integer o(128, 0, PUBLIC);
    aes.compute(o.bits.data(), c.bits.data());
    cout << o.reveal<string>(PUBLIC) << endl;
}

void aes_gcm_enc_test(NetIO* io, int party) {
    unsigned char keyc[] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    reverse(keyc, keyc + 16);
    Integer key(128, keyc, ALICE);

    unsigned char msg[] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59,
                           0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53,
                           0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
                           0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
                           0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a,
                           0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
    size_t msg_len = sizeof(msg);
    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    size_t aad_len = sizeof(aad);

    unsigned char iv[] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                          0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};

    size_t iv_len = sizeof(iv);

    unsigned char* ctxt = new unsigned char[msg_len];
    unsigned char tag[16];

    auto start = emp::clock_start();
    AES_GCM aesgcm(key);
    aesgcm.enc_finished_msg(io, ctxt, tag, iv, iv_len, msg, msg_len, aad, aad_len, party);

    cout << "time: " << emp::time_from(start) << " us" << endl;
    cout << "tag: ";
    for (int i = 0; i < 16; i++) {
        cout << hex << (int)tag[i];
    }
    cout << endl;

    cout << "ctxt: ";
    for (int i = 0; i < msg_len; i++) {
        cout << hex << (int)ctxt[i];
    }
    cout << endl;

    delete[] ctxt;
}

void aes_gcm_dec_test(NetIO* io, int party) {
    unsigned char keyc[] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    reverse(keyc, keyc + 16);
    Integer key(128, keyc, ALICE);

    // unsigned char msg[] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59,
    //                        0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53,
    //                        0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
    //                        0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    //                        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a,
    //                        0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};

    unsigned char msg[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t msg_len = sizeof(msg);

    unsigned char aad[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
                           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};

    size_t aad_len = sizeof(aad);

    unsigned char iv[] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                          0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};

    size_t iv_len = sizeof(iv);

    unsigned char ctxt[] = {0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72,
                            0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f,
                            0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac,
                            0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
                            0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3,
                            0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91};

    size_t ctxt_len = sizeof(ctxt);

    unsigned char tag[] = {0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
                           0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47};

    auto start = emp::clock_start();
    AES_GCM aesgcm(key);
    bool res =
      aesgcm.dec_finished_msg(io, msg, ctxt, ctxt_len, tag, iv, iv_len, aad, aad_len, party);

    cout << "time: " << emp::time_from(start) << " us" << endl;
    cout << endl;
    if (party == ALICE) {
        cout << "ALICE res: " << res << endl;
        cout << "ALICE msg: ";
        for (int i = 0; i < msg_len; i++) {
            cout << hex << (int)msg[i];
        }
        cout << endl;
    } else {
        cout << "BOB res: " << res << endl;
        cout << "BOB msg: ";
        for (int i = 0; i < msg_len; i++) {
            cout << hex << (int)msg[i];
        }
        cout << endl;
    }
}

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    setup_backend(io, party);

    //aes_test();
    //aes_gcm_enc_test(io, party);
    aes_gcm_dec_test(io, party);
    cout << "AND gates: " << dec << CircuitExecution::circ_exec->num_and() << endl;
    finalize_backend();
    delete io;
}