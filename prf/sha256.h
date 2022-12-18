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

    Integer sha256_h[VALLEN] = {
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

    SHA_256(){};
    ~SHA_256(){};
    void padding(vector<Integer>& input_data, Integer input);
    void update(Integer* dig, vector<Integer> input_data);
    void chunk_compress(Integer* input_h, Integer* chunk);
    void digest(Integer* res, Integer input);
};

#endif
