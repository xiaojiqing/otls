#include "backend/switch.h"

#ifndef THREADING
CircuitExecution* gc_circ_buf = nullptr;
ProtocolExecution* gc_prot_buf = nullptr;
CircuitExecution* zk_circ_buf = nullptr;
ProtocolExecution* zk_prot_buf = nullptr;
#else
__thread CircuitExecution* gc_circ_buf = nullptr;
__thread ProtocolExecution* gc_prot_buf = nullptr;
__thread CircuitExecution* zk_circ_buf = nullptr;
__thread ProtocolExecution* zk_prot_buf = nullptr;
#endif
