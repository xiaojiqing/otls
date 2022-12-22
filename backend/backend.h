#ifndef PADO_BACKEND_H__
#define PADO_BACKEND_H__
#include "emp-tool/emp-tool.h"
#include "backend/pado_gen.h"
#include "backend/pado_eva.h"
using namespace emp;

template<typename IO>
inline PADOParty<IO>* setup_backend(IO* io, int party, int batch_size = 1024) {
	if(party == ALICE) {
		HalfGateGen<IO> * t = new HalfGateGen<IO>(io);
		CircuitExecution::circ_exec = t;
		ProtocolExecution::prot_exec = new PADOGen<IO>(io, t);
	} else {
		HalfGateEva<IO> * t = new HalfGateEva<IO>(io);
		CircuitExecution::circ_exec = t;
		ProtocolExecution::prot_exec = new PADOEva<IO>(io, t);
	}
	return (PADOParty<IO>*)ProtocolExecution::prot_exec;
}


inline void finalize_backend() {
	delete CircuitExecution::circ_exec;
	delete ProtocolExecution::prot_exec;
}

template<typename IO>
inline PADOParty<IO>* swap_role(int party) {
	PADOParty<IO>* p = (PADOParty<IO>*)ProtocolExecution::prot_exec;
	if(p->cur_party == party) {
		error("party misaligned!");
	}
	IKNP<IO> * old_ot = p->ot;
	IKNP<IO> * new_ot = new IKNP<IO>(old_ot->io, true);
	block k0[128], k1[128];
	bool s[128];
	if(party == ALICE) {
		auto t = new HalfGateGen<IO>(p->io);
		block_to_bool(s, t->delta);
		old_ot->recv_rot(k0, s, 128);
		new_ot->setup_send(s, k0);

		auto pro = new PADOGen<IO>(p->io, t, new_ot);
		finalize_backend();
		CircuitExecution::circ_exec = t;
		ProtocolExecution::prot_exec = pro;
	} else {
		auto t = new HalfGateEva<IO>(p->io);

		old_ot->send_rot(k0, k1, 128);
		new_ot->setup_recv(k0, k1);
		auto pro = new PADOEva<IO>(p->io, t, new_ot);
		finalize_backend();
		CircuitExecution::circ_exec = t;
		ProtocolExecution::prot_exec = pro;
	}
	return (PADOParty<IO>*)ProtocolExecution::prot_exec;
}
#endif
