#ifndef PADO_COM_COV_H
#define PADO_COM_COV_H
#include <openssl/bn.h>
#include "emp-tool/emp-tool.h"

using namespace emp;
template<typename IO>
class ComConv { public:
	IO * io;
	block Delta = zero_block;
	BIGNUM * aDelta = nullptr;
	Hash hash;
	CCRH ccrh;
	unsigned char com[Hash::DIGEST_SIZE];
	BIGNUM * q;
	BN_CTX * ctx;
	block com_seed;
	ComConv(IO *io, BIGNUM * q2): io(io) {
		q = BN_new();
		BN_copy(this->q, q2);
		ctx = BN_CTX_new();
	}
 	~ComConv() {
		BN_free(q);
		if(aDelta!=nullptr)
			BN_free(aDelta);
		BN_CTX_free(ctx);
	}
	
	void commitDelta(block * dptr = nullptr, BIGNUM* aDelta = nullptr) {
		if(Delta!= nullptr) {
			PRG prg;
			prg.random_data(&com_seed, sizeof(block));
			hash.put(&com_seed, sizeof(block));

			hash.put(dptr, sizeof(block));
			unsigned char arr[1000];
			int length = BN_bn2bin(aDelta, arr);
			hash.put(&length, sizeof(int));
			hash.put(arr, length);
			hash.digest(com);
			io->send_data(com, Hash::DIGEST_SIZE);
			Delta = *dptr;
			this->aDelta = BN_new();
			BN_copy(this->aDelta, aDelta);
		} else {
			io->recv_data(com, Hash::DIGEST_SIZE);
		}
	}

	void convert(vector<BIGNUM*> & aMACs, vector<block> & bMACs) {
		vector<BIGNUM*> msg; msg.resize(bMACs.size());
		for(int i = 0; i < bMACs.size(); ++i) {
			msg[i] = BN_new();
			recv_bn(io, msg[i]);
		}

		for(int i = 0; i < bMACs.size(); ++i) {
			H(aMACs[i], bMACs[i], q);	
			if(getLSB(bMACs[i])) {
				BN_sub(aMACs[i], msg[i], aMACs[i]);
				BN_mod_add(aMACs[i], aMACs[i], q, q, ctx);
			}
		}
	}

	
	void convert(vector<BIGNUM*> & aKEYs, vector<block> & bKEYs, block Delta, BIGNUM* aDelta) {
		vector<BIGNUM*> msg; msg.resize(bKEYs.size());
		for(int i = 0; i < bKEYs.size(); ++i)
			msg[i] = BN_new();
		 
		convert(com_seed, msg, aKEYs, bKEYs);
		for(int i = 0; i < msg.size(); ++i)
			send_bn(io, msg[i]);
	}

	void convert(block seed, vector<BIGNUM*>& msg,
			vector<BIGNUM*> & aKEYs, vector<block> & bKEYs) {
		assert(aKEYs.size() == bKEYs.size());
		for(int i = 0; i < aKEYs.size(); ++i) {
			H(aKEYs[i], bKEYs[i], q);
			H(msg[i], bKEYs[i] ^ Delta, q);
			BN_add(msg[i], msg[i], aKEYs[i]);
			BN_mod_add(msg[i], msg[i], aDelta, q, ctx);
		}
	}

	bool open() {
		if(aDelta != nullptr) {
			//send Delta, aDelta, seed
		} else {
			//check Delta, aDelta, seed,
			//check msg
		}
	}
};
#endif// PADO_COM_COV_H
