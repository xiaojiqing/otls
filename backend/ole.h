#ifndef PADO_OLE_H
#define PADO_OLE_H
#include <openssl/bn.h>
#include "emp-ot/emp-ot.h"

template<typename IO>
class OLE { public:
	IO * io;
	COT<IO>* ot;
	int party;
	BN_CTX * ctx;
	OLE(IO* io, COT<IO>* ot, int party): io(io), ot(ot), party(party) {
		ctx = BN_CTX_new();
	}
	
	~OLE() {
		BN_CTX_free(ctx);
	}

	void H(BIGNUM*out, block b, BIGNUM* q) {
		uint64_t aa = BN_get_word(q);
		BN_set_word(out, b[0] % aa);
	}

	
	//BN_new all memory
	void compute(vector<BIGNUM*> & out, const vector<BIGNUM *>& in, BIGNUM* q, int bit_length) {
		assert(out.size() == in.size());
		unsigned char arr[1000];
		if(party == ALICE) {
			block * raw = new block[out.size()*bit_length];
			ot->send_cot(raw, out.size()*bit_length);
			BIGNUM *pad1 = BN_new(), *pad2 = BN_new(), 
					 *msg = BN_new(),  *tmp = BN_new(), *tmp2 = BN_new();
			for(int i = 0; i < out.size(); ++i) {
				BN_zero(out[i]);
				for(int j = 0; j < bit_length; ++j) {
					H(pad1, raw[i*bit_length+j], q);
					H(pad2, raw[i*bit_length+j] ^ ot->Delta, q);
					BN_add(msg, pad1, pad2);
					BN_mod_add(msg, msg, in[i], q, ctx);

//
					BN_zero(tmp2);
					BN_set_bit(tmp2, j);
					BN_sub(tmp, q, pad1);
					BN_mod_mul(tmp, tmp2, tmp, q, ctx);
					BN_mod_add(out[i], out[i], tmp, q, ctx);

//
					int length = BN_bn2bin(msg, arr);
					io->send_data(&length, sizeof(int));
					io->send_data(arr, length);
				}
			}
			delete[] raw;
			BN_free(pad1);
			BN_free(pad2);
			BN_free(msg);
			BN_free(tmp);
			BN_free(tmp2);
		} else if (party == BOB) {
			bool * bits = new bool[out.size()*bit_length];
			for(int i = 0; i < out.size(); ++i)
				for(int j = 0; j < bit_length; ++j)
					bits[i*bit_length+j] = (BN_is_bit_set(in[i], j) == 1);

			block * raw = new block[out.size()*bit_length];
			ot->recv_cot(raw, bits, out.size()*bit_length);

			BIGNUM * pad = BN_new(), *msg=BN_new(), *tmp2 = BN_new(), 
					*tmp = BN_new();
			for(int i = 0; i < out.size(); ++i) {
				BN_zero(out[i]);
				for(int j = 0; j < bit_length; ++j) {
					int length = -1;
					io->recv_data(&length, sizeof(int));
					io->recv_data(arr, length);
					BN_bin2bn(arr, length, msg);

					H(pad, raw[i*bit_length+j],  q);
					if(bits[i*bit_length+j]) {
						BN_sub(msg, msg, pad);
						BN_mod_add(msg, msg, q, q, ctx);
					} else {
						BN_copy(msg, pad);
					} //msg <- si


					BN_zero(tmp2);
					BN_set_bit(tmp2, j);
					BN_mod_mul(tmp, tmp2, msg, q, ctx);
					BN_mod_add(out[i], out[i], tmp, q, ctx);
				}
			}
			delete[] bits;
			delete[] raw;
			BN_free(pad);
			BN_free(msg);
			BN_free(tmp);
			BN_free(tmp2);
		}
	
	}

	uint64_t H(block b, uint64_t q) {
		return b[0] % q;
	}
	
	void compute(vector<uint64_t> & out, const vector<uint64_t>& in, uint64_t q) {
		if (out.size() < in.size())
			out.resize(in.size());
		if(party == ALICE) {
			uint64_t *pad = new uint64_t[out.size()*64];
			uint64_t *msg = new uint64_t[out.size()*64];
			block * raw = new block[out.size()*64];
			ot->send_cot(raw, out.size()*64);
			for(int i = 0; i < out.size(); ++i) {
				out[i] = 0;
				for(int j = 0; j < 64; ++j) {
					pad[i*64+j] = H(raw[i*64+j], q);
					msg[i*64+j] = (pad[i*64+j] + H(raw[i*64+j] ^ ot->Delta, q) + in[i])%q;
					__uint128_t tmp = 1ULL<<j;
					tmp *= (q - pad[i*64+j]);
					tmp = tmp % q;
					out[i] = (out[i] + tmp)%q;
				}
			}
			io->send_data(msg, out.size()*64*sizeof(uint64_t));
			delete[] pad;
			delete[] msg;
			delete[] raw;
		} else if (party == BOB) {
			uint64_t *pad = new uint64_t[out.size()*64];
			uint64_t *msg = new uint64_t[out.size()*64];
			bool * bits = new bool[out.size()*64];
			for(int i = 0; i < out.size(); ++i)
				for(int j = 0; j < 64; ++j)
					bits[i*64+j] = (((in[i]>>j)&0x1)==0x1);

			block * raw = new block[out.size()*64];
			ot->recv_cot(raw, bits, out.size()*64);
			io->recv_data(msg, out.size()*64*sizeof(uint64_t));

			for(int i = 0; i < out.size(); ++i) {
				out[i] = 0;
				for(int j = 0; j < 64; ++j) {
					uint64_t v = H(raw[i*64+j],  q);
					if(bits[i*64+j]) 
						v = (msg[i*64+j] - v + q)%q;
					__uint128_t tmp = 1ULL<<j;
					tmp *= v;
					tmp = tmp % q;
					out[i] = (out[i] + tmp)%q;
				}
			}
			delete[] pad;
			delete[] msg;
			delete[] bits;
			delete[] raw;
		}
	}
	
};
#endif //