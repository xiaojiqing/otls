#ifndef Online_PADO_GEN_H__
#define Online_PADO_GEN_H__
#include "backend/pado_party.h"

template <typename IO>
class OnlinePADOGen : public PADOParty<IO> {
   public:
    OnlineHalfGateGen<IO>* gc;
    PRG prg;
    OnlinePADOGen(IO* io, OnlineHalfGateGen<IO>* gc, IKNP<IO>* in_ot = nullptr)
        : PADOParty<IO>(io, ALICE, in_ot) {
        this->gc = gc;
        if (in_ot == nullptr) {
            bool delta_bool[128];
            block_to_bool(delta_bool, gc->delta);
            this->ot->setup_send(delta_bool);
        }
    }
    void set_seed(block seed) { prg = PRG(&seed); }

    void feed(block* label, int party, const bool* b, int length) {
        block* label2 = new block[length];
        prg.random_block(label, length);
        for (int i = 0; i < length; ++i)
            label2[i] = label[i] ^ gc->delta;

        if (party == ALICE) {
            for (int i = 0; i < length; ++i) {
                if (b[i])
                    this->io->send_block(label2 + i, 1);
                else
                    this->io->send_block(label + i, 1);
            }
        } else {
            this->ot->send(label, label2, length);
        }
    }

    //reveal with check
    void reveal(bool* b, int party, const block* label, int length) {
        for (int i = 0; i < length; ++i) {
            bool lsb = getLSB(label[i]);
            //if (party == BOB or party == PUBLIC) {
            if (party == BOB) {
                this->io->send_data(&lsb, 1);
                b[i] = false;
            } else if (party == ALICE) {
                bool tmp;
                this->io->recv_data(&tmp, 1);
                b[i] = (tmp != lsb);
            }
        }
        if (party == PUBLIC)
            this->io->recv_data(b, length);
    }
};
#endif