#include "backend/com_conv.h"
#include "backend/backend.h"
#include <iostream>

using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	int port, party;
	const int array_len = 10;
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
	auto prot = (PADOParty<NetIO>*)(ProtocolExecution::prot_exec);
	IKNP<NetIO> * cot = prot->ot;
	bool * val = new bool[array_len];
	vector<block> raw(array_len);
	BIGNUM* aDelta = BN_new();

	if(party == ALICE) {
		BN_rand(aDelta, 256, 0, 0);
		BN_mod(aDelta, aDelta, q, ctx);
		cot->send_cot(raw.data(), array_len);
		conv.commitDelta(&(cot->Delta), aDelta);
	} else {
		PRG prg; prg.random_bool(val, array_len);
		cot->recv_cot(raw.data(), val, array_len);
		conv.commitDelta();
	}
	vector<BIGNUM *> aAuth; aAuth.resize(array_len);
	for(int i = 0; i < array_len; ++i)
		aAuth[i] = BN_new();
	if(party == ALICE) {
		conv.convert_send(aAuth, raw);
		conv.open();	
	} else {
		conv.convert_recv(aAuth, raw);
		bool res = conv.open(raw);	
		if(res)
			cout <<"opened fine!\n";
		else
			cout <<"cheat!\n";
	}
	// consistency check.
	


	

	//	delete cot;
	finalize_backend();
	for(int i = 0; i < 1; ++i)
		delete ios[i];

}