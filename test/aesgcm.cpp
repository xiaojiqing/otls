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

void ghash_test() {
    // block h = makeBlock(0xb83b533708bf535d, 0x0aa6e52980d53b78);
    // block a = zero_block;
    // block c1 = makeBlock(0x42831ec221777424, 0x4b7221b784d0d49c);
    // block c2 = makeBlock(0xe3aa212f2c02a4e0, 0x35c17e2329aca12e);
    // block c3 = makeBlock(0x21d514b25466931c, 0x7d8f6a5aac84aa05);
    // block c4 = makeBlock(0x1ba30b396a0aac97, 0x3d58e091473f5985);
    // block x[5] = {a, c1, c2, c3, c4};
    // //cout << ghash(h, x, 5) << endl;

    block a = makeBlock(0x7b5b546573745665, 0x63746f725d53475d);
    block b = makeBlock(0x4869285368617929, 0x5b477565726f6e5d);
    block res = zero_block;
    gfmul(a, b, &res);
    cout << res << endl;
    cout << mulBlock(a, b) << endl;
}

void aes_test() {
    Integer a(128, 2, ALICE);
    Integer b(128, 0, PUBLIC);
    Bit* c = new Bit[256];
    memcpy(c, a.bits.data(), 128);
    memcpy(c + 128, b.bits.data(), 128);
    Integer o(128, 0, PUBLIC);
    aes.compute(o.bits.data(), c);
    cout << o.reveal<string>() << endl;
    delete[] c;
}

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    setup_backend(io, party);

    aes_test();

    cout << "AND gates: " << dec << CircuitExecution::circ_exec->num_and() << endl;
    finalize_backend();
    delete io;
    //mul_test();
}