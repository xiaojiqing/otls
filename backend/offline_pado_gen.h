#ifndef Offline_PADO_GEN_H__
#define Offline_PADO_GEN_H__
#include "backend/pado_party.h"
#include "offline_hg_gen.h"

class OfflinePADOGen : public ProtocolExecution {
   public:
    OfflineHalfGateGen* gc;
    block seed;
    PRG prg;
    OfflinePADOGen(OfflineHalfGateGen* gc) : ProtocolExecution(ALICE) {
        this->gc = gc;
        PRG().random_block(&seed, 1);
        prg = PRG(&seed);
    }

    void feed(block* label, int party, const bool* b, int length) {
        prg.random_block(label, length);
    }

    void reveal(bool* b, int party, const block* label, int length) {}
};
#endif