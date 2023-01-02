#ifndef PADO_VOPE_H
#define PADO_VOPE_H
#include "emp-ot/emp-ot.h"
#include "backend/bn_utils.h"
#include "cipher/aesgcm.h"
#include <iostream>
template<typename IO>
class VOPE { public:
	IO * io;
	COT<IO>* ot;
	CCRH ccrh;
	GaloisFieldPacking pack;
	VOPE(IO* io, COT<IO>* ot): io(io), ot(ot) {
	}

	~VOPE() {
	}
 
	void compute_recv(block * out, int length) {
		block * M = new block[length*128];
		bool * bits = new bool[length*128];
		PRG prg; prg.random_bool(bits, length*128);
		ot->recv_cot(M, bits, length*128);
		block diff[2];
		diff[0] = zero_block;
		io->recv_data(diff+1, sizeof(block));
		
		for(int i = 0; i < length*128; ++i) {
			M[i] = M[i] ^ diff[bits[i]];
		}

		block * U = M + length;
		block *t1 = M + 2*length;
		block *t2 = M + 3*length;
		for(int i = 0; i < length; ++i) {
			pack.packing(M+i, M + i*128);
			U[i] = bool_to_block(bits + i * 128);
		}
		//M = K + U Delta
		out[0] = M[0];
		out[1] = U[0];
		for(int i = 1; i < length; ++i) {
			for(int j = 0; j <= i; ++j) {
				t1[j] = mulBlock(out[j], M[i]);
				t2[j] = mulBlock(out[j], U[i]);
			}
			out[0] = t1[0];
			for(int j = 1; j <= i; ++j)
				out[j] = t2[j-1] ^ t1[j];
			out[i+1] = t2[i];
		}
		delete[] M;
		delete[] bits;
	}
	void compute_send(block * out, block h, int length) {
		block * K = new block[length*128];
		ot->send_cot(K, length*128);
		block diff = h ^ ot->Delta;
		io->send_data(&diff, sizeof(block));
		io->flush();
		pack.packing(out, K);
		block tmp;
		for(int i = 1; i < length; ++i) {
			pack.packing(&tmp, K + i * 128);
			*out = mulBlock(*out, tmp);
		}
		delete[] K;
	}
};

#endif// PADO_VOPE_H