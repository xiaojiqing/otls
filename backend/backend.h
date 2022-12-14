#ifndef EMP_SEMIHONEST_H__
#define EMP_SEMIHONEST_H__
#include "backend/pado_gen.h"
#include "backend/pado_eva.h"

namespace emp {

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

}
#endif
