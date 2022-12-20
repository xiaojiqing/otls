#include "emp-tool/emp-tool.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "utils.h"
#include "backend/backend.h"
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

using std::string;
using std::vector;
using namespace std;
using namespace emp;

void sha256test() {
    SHA_256 sha;
    Integer* dig = new Integer[sha.DIGLEN];
    vector<uint32_t> outhex;

    string str = "01234567890123456789012345678901";

    Integer input = str_to_int(str, PUBLIC);
    auto start = clock_start();
    sha.digest(dig, input);
    cout << "time: " << time_from(start) << "us" << endl;
    print_hex_32(dig, sha.DIGLEN);

    delete[] dig;
}

void hmac_sha256test() {
    HMAC_SHA_256 hmac256 = HMAC_SHA_256();
    Integer* dig = new Integer[hmac256.DIGLEN];

    string key_str = "01234567890123456789012345678901";
    string msg_str = "master secret0123456789012345678901234567890101234567890123456789012345678901";
    Integer key = str_to_int(key_str, PUBLIC);
    Integer msg = str_to_int(msg_str, PUBLIC);
    auto start = clock_start();
    hmac256.hmac_sha_256(dig, key, msg);
    cout << "time: " << time_from(start) << "us" << endl;

    // cout << "call: " << hmac256.SHA256_call << endl;
    cout << "hmac-sha256: ";
    print_hex_32(dig, hmac256.DIGLEN);
    delete[] dig;
}

void hmac_sha256circ() {
    HMAC_SHA_256 hmac = HMAC_SHA_256();
    Integer* dig = new Integer[hmac.DIGLEN];
    int keylen = 256;
    int msglen = 530;
    Integer keyA = Integer(keylen, 0, ALICE);
    Integer keyB = Integer(keylen, 1, BOB);

    Integer msgA = Integer(msglen, 0, ALICE);
    Integer msgB = Integer(msglen, 1, BOB);

    Integer key = keyA ^ keyB;
    Integer msg = msgA ^ msgB;
    auto start = clock_start();
    hmac.hmac_sha_256(dig, key, msg);
    cout << "time: " << time_from(start) << "us" << endl;

    cout << "CALL SHA256: " << hmac.SHA256_call << " times" << endl;
    delete[] dig;
}

int main(int argc, char** argv) {
    // setup_plain_prot(true, "hmacsha256.txt");
    // //setup_plain_prot(false, "");
    // hmac_sha256test();
    // cout << "AND gates: " << CircuitExecution::circ_exec->num_and() << endl;
    // finalize_plain_prot();

    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);
    setup_backend(io, party);

    hmac_sha256circ();
    //sha256test();
    cout << "AND gates: " << CircuitExecution::circ_exec->num_and() << endl;
    finalize_backend();

    delete io;
}
