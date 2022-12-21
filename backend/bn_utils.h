#ifndef PADO_BN_UTILS_H__
#define PADO_BN_UTILS_H__

#include <openssl/bn.h>
#include "emp-tool/emp-tool.h"

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

inline void recv_bn(NetIO* io, BIGNUM*bn) {
	unsigned char arr[1000];
	uint32_t length = -1;
	io->recv_data(&length, sizeof(uint32_t));
	io->recv_data(arr, length);
	BN_bin2bn(arr, length, bn);
}

#endif// PADO_BN_UTILS_H__
