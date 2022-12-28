#ifndef PADO_OPT_HALFGATE_EVA_
#define PADO_OPT_HALFGATE_EVA_
#include "emp-tool/emp-tool.h"
#include "backend/bn_utils.h"
using namespace emp;
inline void garble_gate_eval_halfgates(block A, block B, 
		block *out, const block *table, uint64_t idx, const AES_KEY *key) {
	block HA, HB, W;
	int sa, sb;
	block tweak1, tweak2;

	sa = getLSB(A);
	sb = getLSB(B);

	tweak1 = makeBlock(2 * idx, (long) 0);
	tweak2 = makeBlock(2 * idx + 1, (long) 0);

	{
		block keys[2];
		block masks[2];

		keys[0] = sigma(A) ^ tweak1;
		keys[1] = sigma(B) ^ tweak2;
		masks[0] = keys[0];
		masks[1] = keys[1];
		AES_ecb_encrypt_blks(keys, 2, key);
		HA = keys[0] ^ masks[0];
		HB = keys[1] ^ masks[1];
	}

	W = HA ^ HB;
	if (sa)
		W = W ^ table[0];
	if (sb) {
		W = W ^ table[1];
		W = W ^ A;
	}
	*out = W;
}

template<typename T>
class OptHalfGateEva:public CircuitExecution{ public:
	int64_t gid = 0;
	PRP prp;
	T * io;
	block fix_point;
	OptHalfGateEva(T * io) :io(io) {
		PRG prg(fix_key);prg.random_block(&fix_point, 1);
	}
	bool is_public(const block & b, int party) {
		return isZero(&b) or isOne(&b);
	}
	block public_label(bool b) override {
		return b? all_one_block : zero_block;
	}
	block and_gate(const block& a, const block& b) override {
		block out, table[2];
		if (isZero(&a) or isOne(&a) or isZero(&b) or isOne(&b)) {
			return _mm_and_si128(a, b);
		} else {
			io->recv_block(table, 2);
			garble_gate_eval_halfgates(a, b, &out, table, gid++, &prp.aes);
			return out;
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
			else return res;
		}
	}
	block not_gate(const block&a) override {
		if (isZero(&a))
			return all_one_block;
		else if (isOne(&a))
			return zero_block;
		else
			return a;
	}
	uint64_t num_and() override {
		return gid;
	}
};
#endif// HALFGATE_EVA_H__
