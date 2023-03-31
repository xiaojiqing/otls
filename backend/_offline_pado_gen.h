#ifndef _OFFLINE_PADO_GEN_H_
#define _OFFLINE_PADO_GEN_H_
#include "_offline_hg_gen.h"
#include "offline_pado_party.h"

template <typename IO>
class _OfflinePADOGen : public OfflinePADOParty {
   public:
    _OfflineHalfGateGen<IO>* gc;
    block seed;
    PRG prg;

    _OfflinePADOGen(_OfflineHalfGateGen<IO>* gc) : OfflinePADOParty(ALICE) {
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