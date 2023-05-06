#include "backend/backend.h"
#include "emp-tool/emp-tool.h"
#include <iostream>

using namespace std;
using namespace emp;

template <typename IO>
void io_test(IO* io, int party) {
    block b0 = zero_block;
    for (int i = 0; i < 10; i++) {
        if (party == ALICE) {
            io->send_block(&b0, 1);
            io->flush();
        } else {
            io->recv_block(&b0, 1);
        }
    }
}
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    auto rounds = io->rounds;
    io_test(io, party);
    cout << "rounds: " << io->rounds - rounds << endl;
    delete io;
}