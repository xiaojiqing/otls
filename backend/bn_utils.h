#ifndef PADO_BN_UTILS_H__
#define PADO_BN_UTILS_H__

#include <openssl/bn.h>
#include "emp-tool/emp-tool.h"
using namespace emp;

inline void H(BIGNUM*out, block b, BIGNUM* q, BN_CTX* ctx, CCRH& ccrh) {
	block arr[2];
	arr[0] = b ^ makeBlock(0, 1);
	arr[1] = b ^ makeBlock(0, 2);
	ccrh.H<2>(arr, arr);

	BN_bin2bn((unsigned char*)arr, 32, out);
	BN_mod(out, out, q, ctx);
}

inline void send_bn(NetIO* io, BIGNUM* bn) {
	unsigned char arr[1000];
	uint32_t length = BN_bn2bin(bn, arr);
	io->send_data(&length, sizeof(uint32_t));
	io->send_data(arr, length);
}

inline void recv_bn(NetIO* io, BIGNUM*bn, Hash * hash = nullptr) {
	unsigned char arr[1000];
	uint32_t length = -1;
	io->recv_data(&length, sizeof(uint32_t));
	io->recv_data(arr, length);
	if(hash != nullptr)
		hash->put(arr, length);
	BN_bin2bn(arr, length, bn);
}

inline bool isZero(const block * b) {
	return _mm_testz_si128(*b,*b) > 0;
}

inline bool isOne(const block * b) {
	__m128i neq = _mm_xor_si128(*b, all_one_block);
	return _mm_testz_si128(neq, neq) > 0;
}
#endif// PADO_BN_UTILS_H__
