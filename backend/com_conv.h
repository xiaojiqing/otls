#ifndef PADO_COM_COV_H
#define PADO_COM_COV_H
#include <openssl/bn.h>
#include <string.h>

#include "backend/bn_utils.h"
#include "emp-tool/emp-tool.h"

using namespace emp;
template<typename IO>
class ComConv { public:
	IO * io;
	block bDelta = zero_block;
	BIGNUM * aDelta = nullptr;
	CCRH ccrh;
	unsigned char com[Hash::DIGEST_SIZE];
	unsigned char msg_com[Hash::DIGEST_SIZE];
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

	void compute_hash(unsigned char res[Hash::DIGEST_SIZE], block seed, block bDelta, BIGNUM* aDelta) {
		Hash hash;
		hash.put(&seed, sizeof(block));
		hash.put(&bDelta, sizeof(block));
		unsigned char arr[1000];
		int length = BN_bn2bin(aDelta, arr);
		hash.put(&length, sizeof(int));
		hash.put(arr, length);
		hash.digest(res);
	}	
	void commitDelta(block * dptr = nullptr, BIGNUM* aDelta = nullptr) {
		if(aDelta!= nullptr) {
			PRG prg;
			prg.random_data(&com_seed, sizeof(block));
			compute_hash(com, com_seed, *dptr, aDelta);
			io->send_data(com, Hash::DIGEST_SIZE);
			bDelta = *dptr;
			this->aDelta = BN_new();
			BN_copy(this->aDelta, aDelta);
		} else {
			io->recv_data(com, Hash::DIGEST_SIZE);
		}
	}

	void convert_recv(vector<BIGNUM*> & aMACs, vector<block> & bMACs) {
		Hash hash;
		vector<BIGNUM*> msg; msg.resize(bMACs.size());
		for(int i = 0; i < bMACs.size(); ++i) {
			msg[i] = BN_new();
			recv_bn(io, msg[i], &hash);
		}
		hash.digest(msg_com);

		for(int i = 0; i < bMACs.size(); ++i) {
			H(aMACs[i], bMACs[i], q, ctx, ccrh);	
			if(getLSB(bMACs[i])) {
				BN_sub(aMACs[i], msg[i], aMACs[i]);
				BN_mod_add(aMACs[i], aMACs[i], q, q, ctx);
			}
		}
		for(int i = 0; i < bMACs.size(); ++i)
			BN_free(msg[i]);
	}


	void convert_send(vector<BIGNUM*> & aKEYs, vector<block> & bKEYs) {
		vector<BIGNUM*> msg; msg.resize(bKEYs.size());
		for(int i = 0; i < bKEYs.size(); ++i)
			msg[i] = BN_new();

		convert(msg, aKEYs, com_seed, bKEYs, bDelta, aDelta);
		for(int i = 0; i < msg.size(); ++i)
			send_bn(io, msg[i]);

		for(int i = 0; i < bKEYs.size(); ++i)
			BN_free(msg[i]);
	}

	void convert(vector<BIGNUM*>& msg, vector<BIGNUM*> & aKEYs, 
			block seed, vector<block> & bKEYs, block local_bDelta, BIGNUM* local_aDelta) {
		assert(aKEYs.size() == bKEYs.size());
		for(int i = 0; i < aKEYs.size(); ++i) {
			H(aKEYs[i], bKEYs[i], q, ctx, ccrh);
			H(msg[i], bKEYs[i] ^ local_bDelta, q, ctx, ccrh);
			BN_add(msg[i], msg[i], aKEYs[i]);
			BN_mod_add(msg[i], msg[i], local_aDelta, q, ctx);
		}
	}

	void check( ){
	}

	void open() {
		io->send_data(&com_seed, sizeof(block));
		io->send_data(&bDelta, sizeof(block));
		send_bn(io, aDelta);
	}
	bool open(vector<block> & bMACs) {
		bool ret = true;
		block tmp_seed, tmp_bDelta;
		BIGNUM* tmp_aDelta = BN_new();
		io->recv_data(&tmp_seed, sizeof(block));
		io->recv_data(&tmp_bDelta, sizeof(block));
		recv_bn(io, tmp_aDelta);
		unsigned char tmp_com[Hash::DIGEST_SIZE];
		compute_hash(tmp_com, tmp_seed, tmp_bDelta, tmp_aDelta);
		ret = ret and (std::strncmp((char *)tmp_com, (char*)com, Hash::DIGEST_SIZE) == 0);

		vector<BIGNUM*> msg; msg.resize(bMACs.size());
		vector<BIGNUM*> tmp_akeys; tmp_akeys.resize(bMACs.size());
		vector<block> tmp_bkeys(bMACs);
		for(int i = 0; i < bMACs.size(); ++i)  {
			tmp_akeys[i] = BN_new();
			msg[i] = BN_new();
			if(getLSB(tmp_bkeys[i]))
				tmp_bkeys[i] = tmp_bkeys[i] ^ tmp_bDelta;
		}
		convert(msg, tmp_akeys, com_seed, tmp_bkeys, tmp_bDelta, tmp_aDelta);
		Hash hash;
		unsigned char arr[1000];
		for(int i = 0; i < bMACs.size(); ++i) {
			uint32_t length = BN_bn2bin(msg[i], arr);
			hash.put(arr, length);
		}
		hash.digest(tmp_com);

		BN_free(tmp_aDelta);
		for(int i = 0; i < bMACs.size(); ++i) {
			BN_free(tmp_akeys[i]);
			BN_free(msg[i]);
		}

		ret = ret and (std::strncmp((char *)tmp_com, (char *)msg_com, Hash::DIGEST_SIZE) == 0);
		return ret;
	}
};
#endif// PADO_COM_COV_H
