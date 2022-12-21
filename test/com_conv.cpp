#include "backend/com_conv.h"
#include "backend/backend.h"
#include <iostream>

using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	int port, party;
	const int num_ole = 6;
	parse_party_and_port(argv, &party, &port);
	NetIO* ios[1];
	for(int i = 0; i < 1; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);


	setup_backend(ios[0], party);

	BIGNUM * q = BN_new(), *n19 = BN_new();
	BN_CTX * ctx = BN_CTX_new();
	BN_set_bit(q, 255);
	BN_set_word(n19, 19);
	BN_sub(q, q, n19);//2^255-19
	ComConv<NetIO> conv(ios[0], q);


	//	delete cot;
	finalize_backend();
	for(int i = 0; i < 1; ++i)
		delete ios[i];

}