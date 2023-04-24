#ifndef __SWITCH_H__
#define __SWITCH_H__
#include "emp-tool/emp-tool.h"
#include "backend/backend.h"
#include "emp-zk/emp-zk.h"

using namespace emp;

static CircuitExecution* gc_circ_buf = nullptr;
static ProtocolExecution* gc_prot_buf = nullptr;
static CircuitExecution* zk_circ_buf = nullptr;
static ProtocolExecution* zk_prot_buf = nullptr;
static CircuitExecution* offline_gc_circ_buf = nullptr;
static ProtocolExecution* offline_gc_prot_buf = nullptr;

void backup_gc_ptr() {
    gc_circ_buf = CircuitExecution::circ_exec;
    gc_prot_buf = ProtocolExecution::prot_exec;
}

void backup_zk_ptr() {
    zk_circ_buf = CircuitExecution::circ_exec;
    zk_prot_buf = ProtocolExecution::prot_exec;
}

void backup_offline_ptr() {
    offline_gc_circ_buf = CircuitExecution::circ_exec;
    offline_gc_prot_buf = ProtocolExecution::prot_exec;
}

template <typename IO>
void setup_protocol(
  IO* io, BoolIO<IO>** ios, int threads, int party, bool ENABLE_OFFLINE_ONLINE = false) {
    setup_zk_bool<BoolIO<IO>>(ios, threads, party);
    backup_zk_ptr();

    if (!ENABLE_OFFLINE_ONLINE) {
        setup_backend<IO>(io, party);
        backup_gc_ptr();
    } else {
        setup_online_backend(io, party);
        backup_gc_ptr();

        setup_offline_backend(io, party);
        backup_offline_ptr();
    }
}

void switch_to_zk() {
    CircuitExecution::circ_exec = zk_circ_buf;
    ProtocolExecution::prot_exec = zk_prot_buf;
}

template <typename IO>
void sync_zk_gc() {
    sync_zk_bool<BoolIO<IO>>();
}

void switch_to_gc() {
    CircuitExecution::circ_exec = gc_circ_buf;
    ProtocolExecution::prot_exec = gc_prot_buf;
}

template <typename IO>
void switch_to_online(int party) {
    auto offline = (OfflinePADOParty*)offline_gc_prot_buf;
    auto online = (PADOParty<IO>*)gc_prot_buf;

    sync_offline_online(offline, online, party);
    switch_to_gc();
}

void finalize_protocol() {
    delete gc_circ_buf;
    delete gc_prot_buf;
    delete zk_circ_buf;
    delete zk_prot_buf;
    delete offline_gc_circ_buf;
    delete offline_gc_prot_buf;
}
#endif