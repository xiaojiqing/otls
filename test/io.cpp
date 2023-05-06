#include "backend/backend.h"
#include "emp-tool/emp-tool.h"
#include <iostream>

using namespace std;
using namespace emp;

template <typename IO>
void io_test(IO* io, IO* io1, int party) {
    block b0 = zero_block, b1 = zero_block;
    if (party == ALICE) {
        io->send_block(&b0, 1);
        // io->flush();
        // io1->recv_block(&b1, 1);
        // io->flush();
        io1->send_block(&b1, 1);
    } else {
        io->recv_block(&b0, 1);
        // io1->send_block(&b1, 1);
        io1->recv_block(&b1, 1);
    }
}
int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    NetIO* io1 = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + 1);
    // setup_backend(io, party);
    io_test(io, io1, party);
    // finalize_backend();
    delete io;
    delete io1;
}