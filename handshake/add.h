#ifndef _ADD_H_
#define _ADD_H_
#include "emp-tool/emp-tool.h"
#include <openssl/bn.h>

using namespace std;
using namespace emp;

inline void addmod(Integer& res, const Integer& a, const Integer& b, BIGNUM* q) {
    unsigned char* intq = new unsigned char[BN_num_bytes(q)];
    BN_bn2bin(q, intq);
    reverse(intq, intq + BN_num_bytes(q));

    // cout << "Q bits: " << BN_num_bits(q) << endl;
    // cout << "Q bytes: " << BN_num_bytes(q) << endl;
    Integer Q(BN_num_bytes(q) * 8, intq, PUBLIC);
    // cout << "Q integer bits: " << Q.size() << endl;
    Integer c = a + b;

    //cout << "c: " << c.reveal<string>() << endl;
    //cout << "Q: " << Q.reveal<string>() << endl;

    c.bits.push_back(Bit(0, PUBLIC));
    Q.bits.push_back(Bit(0, PUBLIC));

    Bit sel = c.geq(Q);
    res = c.select(sel, c - Q);
    res.bits.pop_back();
    //cout << sel.reveal<bool>() << endl;
    delete[] intq;
}
#endif