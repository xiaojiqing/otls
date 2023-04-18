
#include "cipher/utils.h"
__thread BristolFormat *aes_ks = nullptr;
__thread BristolFormat *aes_enc_ks = nullptr;

static const char* aes_ks_file = "cipher/circuit_files/aes128_ks.txt";

static const char* aes_enc_file = "cipher/circuit_files/aes128_with_ks.txt";

void init_files() {
    delete aes_ks;
    delete aes_enc_ks;

    aes_ks = new BristolFormat(aes_ks_file);
    aes_enc_ks = new BristolFormat(aes_enc_file);
}
