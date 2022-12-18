#include "emp-tool/emp-tool.h"
#include "sha256.h"
#include "sha512.h"
#include "hmac_sha256.h"
#include "utils.h"
#include "emp-sh2pc/emp-sh2pc.h"
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
    sha.digest(dig, input);

    print_hex_32(dig,sha.DIGLEN);
    delete[] dig;
}

void sha512test() {
    SHA_512 sha = SHA_512();
    Integer* dig = new Integer[sha.DIGLEN];
    string msg_str = "012345678901234567890123456789012345678901234567";
    Integer input = str_to_int(msg_str, PUBLIC);
    // Integer inputA = Integer(1536, 0, ALICE);
    // Integer inputB = Integer(1536, 1, BOB);

    // Integer input = inputA ^ inputB;
    sha.digest(dig, input);

    cout << "SHA512: ";
    print_hex_64(dig, sha.DIGLEN);
    delete[] dig;
}

void hmac_sha256test() {
    HMAC_SHA_256 hmac256 = HMAC_SHA_256();
    Integer* dig = new Integer[hmac256.DIGLEN];

    string key_str = "012345678901234567890123456789012345678901234567";
    string msg_str = "abcdefabcdefabcdefabcdefabcdefabcdef";
    Integer key = str_to_int(key_str, PUBLIC);
    Integer msg = str_to_int(msg_str, PUBLIC);
    hmac256.hmac_sha_256(dig, key, msg);

    // cout << "call: " << hmac256.SHA256_call << endl;
    cout << "hmac-sha256: ";
    print_hex_32(dig, hmac256.DIGLEN);
    delete[] dig;
}

void hmac_sha256circ() {
    HMAC_SHA_256 hmac = HMAC_SHA_256();
    Integer* dig = new Integer[hmac.DIGLEN];
    int keylen = 256;
    int msglen = 296;
    Integer keyA = Integer(keylen, 0, ALICE);
    Integer keyB = Integer(keylen, 1, BOB);

    Integer msgA = Integer(msglen, 0, ALICE);
    Integer msgB = Integer(msglen, 1, BOB);

    Integer key = keyA ^ keyB;
    Integer msg = msgA ^ msgB;

    hmac.hmac_sha_256(dig, key, msg);
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
    setup_semi_honest(io, party);

    hmac_sha256circ();
    //sha256test();
    cout << "AND gates: " << CircuitExecution::circ_exec->num_and() << endl;
    finalize_semi_honest();

    delete io;
}
