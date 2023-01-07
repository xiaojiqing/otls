#include "handshake/handshake.h"

#include "backend/backend.h"
#include <iostream>

using namespace std;

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    setup_backend(io, party);
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* q = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP_get_curve(group, q, NULL, NULL, ctx);

    unsigned char* a = new unsigned char[32];
    BN_bn2bin(q, a);
    for (int i = 0; i < 32; i++) {
        cout << hex << (int)a[i];
    }
    cout << dec << endl;

    EC_GROUP_free(group);
    BN_free(q);
    BN_CTX_free(ctx);

    finalize_backend();
    delete io;
}