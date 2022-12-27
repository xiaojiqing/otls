#ifndef SHA256_H
#define SHA256_H

#include "emp-tool/emp-tool.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace emp;
using std::vector;

class SHA_256 {
   public:
    static const int DIGLEN = 8;
    static const int VALLEN = 8;
    static const int WORDLEN = 32;
    static const int KLEN = 64;
    static const int CHUNKLEN = 512;

    const Integer sha256_h[VALLEN] = {
      Integer(WORDLEN, 0x6a09e667UL, PUBLIC), Integer(WORDLEN, 0xbb67ae85UL, PUBLIC), 
      Integer(WORDLEN, 0x3c6ef372UL, PUBLIC), Integer(WORDLEN, 0xa54ff53aUL, PUBLIC),
      Integer(WORDLEN, 0x510e527fUL, PUBLIC), Integer(WORDLEN, 0x9b05688cUL, PUBLIC), 
      Integer(WORDLEN, 0x1f83d9abUL, PUBLIC), Integer(WORDLEN, 0x5be0cd19UL, PUBLIC)};

    const Integer sha256_k[KLEN] = {
      Integer(WORDLEN, 0x428a2f98UL, PUBLIC), Integer(WORDLEN, 0x71374491UL, PUBLIC), 
      Integer(WORDLEN, 0xb5c0fbcfUL, PUBLIC), Integer(WORDLEN, 0xe9b5dba5UL, PUBLIC), 
      Integer(WORDLEN, 0x3956c25bUL, PUBLIC), Integer(WORDLEN, 0x59f111f1UL, PUBLIC),
      Integer(WORDLEN, 0x923f82a4UL, PUBLIC), Integer(WORDLEN, 0xab1c5ed5UL, PUBLIC), 
      Integer(WORDLEN, 0xd807aa98UL, PUBLIC), Integer(WORDLEN, 0x12835b01UL, PUBLIC), 
      Integer(WORDLEN, 0x243185beUL, PUBLIC), Integer(WORDLEN, 0x550c7dc3UL, PUBLIC),
      Integer(WORDLEN, 0x72be5d74UL, PUBLIC), Integer(WORDLEN, 0x80deb1feUL, PUBLIC), 
      Integer(WORDLEN, 0x9bdc06a7UL, PUBLIC), Integer(WORDLEN, 0xc19bf174UL, PUBLIC), 
      Integer(WORDLEN, 0xe49b69c1UL, PUBLIC), Integer(WORDLEN, 0xefbe4786UL, PUBLIC),
      Integer(WORDLEN, 0x0fc19dc6UL, PUBLIC), Integer(WORDLEN, 0x240ca1ccUL, PUBLIC), 
      Integer(WORDLEN, 0x2de92c6fUL, PUBLIC), Integer(WORDLEN, 0x4a7484aaUL, PUBLIC), 
      Integer(WORDLEN, 0x5cb0a9dcUL, PUBLIC), Integer(WORDLEN, 0x76f988daUL, PUBLIC),
      Integer(WORDLEN, 0x983e5152UL, PUBLIC), Integer(WORDLEN, 0xa831c66dUL, PUBLIC), 
      Integer(WORDLEN, 0xb00327c8UL, PUBLIC), Integer(WORDLEN, 0xbf597fc7UL, PUBLIC), 
      Integer(WORDLEN, 0xc6e00bf3UL, PUBLIC), Integer(WORDLEN, 0xd5a79147UL, PUBLIC),
      Integer(WORDLEN, 0x06ca6351UL, PUBLIC), Integer(WORDLEN, 0x14292967UL, PUBLIC), 
      Integer(WORDLEN, 0x27b70a85UL, PUBLIC), Integer(WORDLEN, 0x2e1b2138UL, PUBLIC), 
      Integer(WORDLEN, 0x4d2c6dfcUL, PUBLIC), Integer(WORDLEN, 0x53380d13UL, PUBLIC),
      Integer(WORDLEN, 0x650a7354UL, PUBLIC), Integer(WORDLEN, 0x766a0abbUL, PUBLIC), 
      Integer(WORDLEN, 0x81c2c92eUL, PUBLIC), Integer(WORDLEN, 0x92722c85UL, PUBLIC), 
      Integer(WORDLEN, 0xa2bfe8a1UL, PUBLIC), Integer(WORDLEN, 0xa81a664bUL, PUBLIC),
      Integer(WORDLEN, 0xc24b8b70UL, PUBLIC), Integer(WORDLEN, 0xc76c51a3UL, PUBLIC), 
      Integer(WORDLEN, 0xd192e819UL, PUBLIC), Integer(WORDLEN, 0xd6990624UL, PUBLIC), 
      Integer(WORDLEN, 0xf40e3585UL, PUBLIC), Integer(WORDLEN, 0x106aa070UL, PUBLIC),
      Integer(WORDLEN, 0x19a4c116UL, PUBLIC), Integer(WORDLEN, 0x1e376c08UL, PUBLIC), 
      Integer(WORDLEN, 0x2748774cUL, PUBLIC), Integer(WORDLEN, 0x34b0bcb5UL, PUBLIC), 
      Integer(WORDLEN, 0x391c0cb3UL, PUBLIC), Integer(WORDLEN, 0x4ed8aa4aUL, PUBLIC),
      Integer(WORDLEN, 0x5b9cca4fUL, PUBLIC), Integer(WORDLEN, 0x682e6ff3UL, PUBLIC), 
      Integer(WORDLEN, 0x748f82eeUL, PUBLIC), Integer(WORDLEN, 0x78a5636fUL, PUBLIC), 
      Integer(WORDLEN, 0x84c87814UL, PUBLIC), Integer(WORDLEN, 0x8cc70208UL, PUBLIC),
      Integer(WORDLEN, 0x90befffaUL, PUBLIC), Integer(WORDLEN, 0xa4506cebUL, PUBLIC), 
      Integer(WORDLEN, 0xbef9a3f7UL, PUBLIC), Integer(WORDLEN, 0xc67178f2UL, PUBLIC)};
    
    const uint32_t plain_sha256_k[KLEN] = {
      0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
      0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
      0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
      0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
      0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
    };

    SHA_256(){};
    ~SHA_256(){};
    void padding(Integer& padded_input, const Integer input);
    void update(Integer* dig, const Integer padded_input);
    void opt_update(uint32_t* plain_dig, const Integer sec_input, unsigned char* pub_input, size_t pub_len);
    void chunk_compress(Integer* input_h, Integer* chunk);
    void opt_chunk_compress(uint32_t* input_h, unsigned char* chunk);
    void digest(Integer* res, Integer input);
    void opt_digest(uint32_t* res, const Integer sec_input, unsigned char* pub_input, size_t pub_len);
};

#endif
