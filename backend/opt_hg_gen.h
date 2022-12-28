#ifndef PADO_OPT_HALFGATE_GEN_
#define PADO_OPT_HALFGATE_GEN_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;
inline void garble_gate_garble_halfgates(block LA0, block A1, block LB0, block B1, block *out0, block *out1, block delta, block *table, uint64_t idx, const AES_KEY *key) {
	long pa = getLSB(LA0);
	long pb = getLSB(LB0);
	block tweak1, tweak2;
	block HLA0, HA1, HLB0, HB1;
	block tmp, W0;

	tweak1 = makeBlock(2 * idx, (uint64_t) 0);
	tweak2 = makeBlock(2 * idx + 1, (uint64_t) 0);

	{
		block masks[4], keys[4];

		keys[0] = sigma(LA0) ^ tweak1;
		keys[1] = sigma(A1) ^ tweak1;
		keys[2] = sigma(LB0) ^ tweak2;
		keys[3] = sigma(B1) ^ tweak2;
		memcpy(masks, keys, sizeof keys);
		AES_ecb_encrypt_blks(keys, 4, key);
		HLA0 = keys[0] ^ masks[0];
		HA1 = keys[1] ^ masks[1];
		HLB0 = keys[2] ^ masks[2];
		HB1 = keys[3] ^ masks[3];
	}

	table[0] = HLA0 ^ HA1;
	if (pb)
		table[0] = table[0] ^ delta;
	W0 = HLA0;
	if (pa)
		W0 = W0 ^ table[0];
	tmp = HLB0 ^ HB1;
	table[1] = tmp ^ LA0;
	W0 = W0 ^ HLB0;
	if (pb)
		W0 = W0 ^ tmp;

	*out0 = W0;
	*out1 = *out0 ^ delta;
}

template<typename T>
class OptHalfGateGen:public CircuitExecution { public:
	int64_t gid = 0;
	block delta;
	PRP prp;
	block seed;
	T * io;
	block fix_point;
	OptHalfGateGen(T * io) :io(io) {
		PRG prg(fix_key);prg.random_block(&fix_point, 1);
		PRG tmp;
		tmp.random_block(&seed, 1);
		block a;
		tmp.random_block(&a, 1);
		set_delta(a);
	}
	bool is_public(const block & b, int party) {
		return isZero(&b) or isOne(&b);
	}
	void set_delta(const block &_delta) {
		this->delta = _mm_or_si128(makeBlock(0L, 1L), _delta);//make_delta(_delta);
	}
	block public_label(bool b) override {
		return b? all_one_block : zero_block;
	}
	bool isDelta(const block & b) {
		__m128i neq = b ^ delta;
		return _mm_testz_si128(neq, neq);
	}

	block and_gate(const block& a, const block& b) override {
		block out[2], table[2];
		if (isZero(&a) or isZero(&b)) {
			return zero_block;
		} else if (isOne(&a)) {
			return b;
		} else if (isOne(&b)){
			return a;
		} else {
			garble_gate_garble_halfgates(a, a ^ delta, b, b ^ delta, 
					&out[0], &out[1], delta, table, gid++, &prp.aes);
			io->send_block(table, 2);
			return out[0];
		}
	}
	block xor_gate(const block&a, const block& b) override {
		if(isOne(&a))
			return not_gate(b);
		else if (isOne(&b))
			return not_gate(a);
		else if (isZero(&a))
			return b;
		else if (isZero(&b))
			return a;
		else {
			block res = a ^ b;
			if (isZero(&res))
				return fix_point;
			if (isDelta(res))
				return fix_point ^ delta;
			else
				return res;//xorBlocks(a, b);
		}
	}
	block not_gate(const block&a) override {
		if (isZero(&a))
			return all_one_block;
		else if (isOne(&a))
			return zero_block;
		else
			return a ^ delta;
	}
	uint64_t num_and() override {
		return gid;
	}

};
#endif