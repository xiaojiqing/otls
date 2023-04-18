#include "backend/switch.h"
__thread CircuitExecution* gc_circ_buf = nullptr;
__thread ProtocolExecution* gc_prot_buf = nullptr;
__thread CircuitExecution* zk_circ_buf = nullptr;
__thread ProtocolExecution* zk_prot_buf = nullptr;

