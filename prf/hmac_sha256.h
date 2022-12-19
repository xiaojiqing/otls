#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include "emp-tool/emp-tool.h"
#include <iostream>
#include <vector>
#include "sha256.h"

using namespace std;
using namespace emp;
using std::vector;

class HMAC_SHA_256 : public SHA_256 {
   public:
    int SHA256_call = 0;
    HMAC_SHA_256(){};
    ~HMAC_SHA_256(){};
    Integer o_pad;
    Integer i_pad;

    Integer o_key_pad;
    Integer i_key_pad;

    void init(Integer key);
    void hmac_sha_256(Integer* res, const Integer key, const Integer msg);
};

#endif
