#ifndef PADO_PARTY_H__
#define PADO_PARTY_H__
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"

namespace emp {

template<typename IO>
class PADOParty: public ProtocolExecution { public:
	IO* io = nullptr;
	IKNP<IO> * ot = nullptr;
	PRG shared_prg;

	block * buf = nullptr;
	bool * buff = nullptr;
	int top = 0;
	int batch_size = 1024*16;

	PADOParty(IO * io, int party) : ProtocolExecution(party) {
		this->io = io;
		ot = new IKNP<IO>(io, true);
		buf = new block[batch_size];
		buff = new bool[batch_size];
	}
	void set_batch_size(int size) {
		delete[] buf;
		delete[] buff;
		batch_size = size;
		buf = new block[batch_size];
		buff = new bool[batch_size];
	}

	~PADOParty() {
		delete[] buf;
		delete[] buff;
		delete ot;
	}
};
}
#endif
