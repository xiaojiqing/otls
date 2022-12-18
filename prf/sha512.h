#ifndef SHA512_H
#define SHA512_H

#include"emp-tool/emp-tool.h"
#include<iostream>
#include<vector>

using namespace std;
using namespace emp;
using std::vector;

class SHA_512{
public:

  static const int DIGLEN = 8;
  static const int VALLEN = 8;
  static const int WORDLEN = 64;
  static const int KLEN = 80;
  static const int CHUNKLEN = 1024;

  Integer sha512_h[VALLEN] =
  {
    Integer(WORDLEN, 0x6a09e667f3bcc908ULL, PUBLIC),
    Integer(WORDLEN, 0xbb67ae8584caa73bULL, PUBLIC),
    Integer(WORDLEN, 0x3c6ef372fe94f82bULL, PUBLIC),
    Integer(WORDLEN, 0xa54ff53a5f1d36f1ULL, PUBLIC),
    Integer(WORDLEN, 0x510e527fade682d1ULL, PUBLIC),
    Integer(WORDLEN, 0x9b05688c2b3e6c1fULL, PUBLIC),
    Integer(WORDLEN, 0x1f83d9abfb41bd6bULL, PUBLIC),
    Integer(WORDLEN, 0x5be0cd19137e2179ULL, PUBLIC)
  };

  const Integer sha512_k[KLEN] =
  {
    Integer(WORDLEN, 0x428a2f98d728ae22ULL, PUBLIC), Integer(WORDLEN, 0x7137449123ef65cdULL, PUBLIC),
    Integer(WORDLEN, 0xb5c0fbcfec4d3b2fULL, PUBLIC), Integer(WORDLEN, 0xe9b5dba58189dbbcULL, PUBLIC),
    Integer(WORDLEN, 0x3956c25bf348b538ULL, PUBLIC), Integer(WORDLEN, 0x59f111f1b605d019ULL, PUBLIC),
    Integer(WORDLEN, 0x923f82a4af194f9bULL, PUBLIC), Integer(WORDLEN, 0xab1c5ed5da6d8118ULL, PUBLIC),
    Integer(WORDLEN, 0xd807aa98a3030242ULL, PUBLIC), Integer(WORDLEN, 0x12835b0145706fbeULL, PUBLIC),
    Integer(WORDLEN, 0x243185be4ee4b28cULL, PUBLIC), Integer(WORDLEN, 0x550c7dc3d5ffb4e2ULL, PUBLIC),
    Integer(WORDLEN, 0x72be5d74f27b896fULL, PUBLIC), Integer(WORDLEN, 0x80deb1fe3b1696b1ULL, PUBLIC),
    Integer(WORDLEN, 0x9bdc06a725c71235ULL, PUBLIC), Integer(WORDLEN, 0xc19bf174cf692694ULL, PUBLIC),
    Integer(WORDLEN, 0xe49b69c19ef14ad2ULL, PUBLIC), Integer(WORDLEN, 0xefbe4786384f25e3ULL, PUBLIC),
    Integer(WORDLEN, 0x0fc19dc68b8cd5b5ULL, PUBLIC), Integer(WORDLEN, 0x240ca1cc77ac9c65ULL, PUBLIC),
    Integer(WORDLEN, 0x2de92c6f592b0275ULL, PUBLIC), Integer(WORDLEN, 0x4a7484aa6ea6e483ULL, PUBLIC),
    Integer(WORDLEN, 0x5cb0a9dcbd41fbd4ULL, PUBLIC), Integer(WORDLEN, 0x76f988da831153b5ULL, PUBLIC),
    Integer(WORDLEN, 0x983e5152ee66dfabULL, PUBLIC), Integer(WORDLEN, 0xa831c66d2db43210ULL, PUBLIC),
    Integer(WORDLEN, 0xb00327c898fb213fULL, PUBLIC), Integer(WORDLEN, 0xbf597fc7beef0ee4ULL, PUBLIC),
    Integer(WORDLEN, 0xc6e00bf33da88fc2ULL, PUBLIC), Integer(WORDLEN, 0xd5a79147930aa725ULL, PUBLIC),
    Integer(WORDLEN, 0x06ca6351e003826fULL, PUBLIC), Integer(WORDLEN, 0x142929670a0e6e70ULL, PUBLIC),
    Integer(WORDLEN, 0x27b70a8546d22ffcULL, PUBLIC), Integer(WORDLEN, 0x2e1b21385c26c926ULL, PUBLIC),
    Integer(WORDLEN, 0x4d2c6dfc5ac42aedULL, PUBLIC), Integer(WORDLEN, 0x53380d139d95b3dfULL, PUBLIC),
    Integer(WORDLEN, 0x650a73548baf63deULL, PUBLIC), Integer(WORDLEN, 0x766a0abb3c77b2a8ULL, PUBLIC),
    Integer(WORDLEN, 0x81c2c92e47edaee6ULL, PUBLIC), Integer(WORDLEN, 0x92722c851482353bULL, PUBLIC),
    Integer(WORDLEN, 0xa2bfe8a14cf10364ULL, PUBLIC), Integer(WORDLEN, 0xa81a664bbc423001ULL, PUBLIC),
    Integer(WORDLEN, 0xc24b8b70d0f89791ULL, PUBLIC), Integer(WORDLEN, 0xc76c51a30654be30ULL, PUBLIC),
    Integer(WORDLEN, 0xd192e819d6ef5218ULL, PUBLIC), Integer(WORDLEN, 0xd69906245565a910ULL, PUBLIC),
    Integer(WORDLEN, 0xf40e35855771202aULL, PUBLIC), Integer(WORDLEN, 0x106aa07032bbd1b8ULL, PUBLIC),
    Integer(WORDLEN, 0x19a4c116b8d2d0c8ULL, PUBLIC), Integer(WORDLEN, 0x1e376c085141ab53ULL, PUBLIC),
    Integer(WORDLEN, 0x2748774cdf8eeb99ULL, PUBLIC), Integer(WORDLEN, 0x34b0bcb5e19b48a8ULL, PUBLIC),
    Integer(WORDLEN, 0x391c0cb3c5c95a63ULL, PUBLIC), Integer(WORDLEN, 0x4ed8aa4ae3418acbULL, PUBLIC),
    Integer(WORDLEN, 0x5b9cca4f7763e373ULL, PUBLIC), Integer(WORDLEN, 0x682e6ff3d6b2b8a3ULL, PUBLIC),
    Integer(WORDLEN, 0x748f82ee5defb2fcULL, PUBLIC), Integer(WORDLEN, 0x78a5636f43172f60ULL, PUBLIC),
    Integer(WORDLEN, 0x84c87814a1f0ab72ULL, PUBLIC), Integer(WORDLEN, 0x8cc702081a6439ecULL, PUBLIC),
    Integer(WORDLEN, 0x90befffa23631e28ULL, PUBLIC), Integer(WORDLEN, 0xa4506cebde82bde9ULL, PUBLIC),
    Integer(WORDLEN, 0xbef9a3f7b2c67915ULL, PUBLIC), Integer(WORDLEN, 0xc67178f2e372532bULL, PUBLIC),
    Integer(WORDLEN, 0xca273eceea26619cULL, PUBLIC), Integer(WORDLEN, 0xd186b8c721c0c207ULL, PUBLIC),
    Integer(WORDLEN, 0xeada7dd6cde0eb1eULL, PUBLIC), Integer(WORDLEN, 0xf57d4f7fee6ed178ULL, PUBLIC),
    Integer(WORDLEN, 0x06f067aa72176fbaULL, PUBLIC), Integer(WORDLEN, 0x0a637dc5a2c898a6ULL, PUBLIC),
    Integer(WORDLEN, 0x113f9804bef90daeULL, PUBLIC), Integer(WORDLEN, 0x1b710b35131c471bULL, PUBLIC),
    Integer(WORDLEN, 0x28db77f523047d84ULL, PUBLIC), Integer(WORDLEN, 0x32caab7b40c72493ULL, PUBLIC),
    Integer(WORDLEN, 0x3c9ebe0a15c9bebcULL, PUBLIC), Integer(WORDLEN, 0x431d67c49c100d4cULL, PUBLIC),
    Integer(WORDLEN, 0x4cc5d4becb3e42b6ULL, PUBLIC), Integer(WORDLEN, 0x597f299cfc657e2aULL, PUBLIC),
    Integer(WORDLEN, 0x5fcb6fab3ad6faecULL, PUBLIC), Integer(WORDLEN, 0x6c44198c4a475817ULL, PUBLIC)
  };

  SHA_512(){};
  ~SHA_512(){};

  int compress_times = 0;
  void padding(vector<Integer>&input_data, Integer input);
  void update(Integer*dig,vector<Integer> input_data);
  void chunk_compress(Integer* input_h, Integer* chunk);
  void digest(Integer* res, Integer input);
};

#endif
