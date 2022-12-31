#ifndef _AES_GCM_H_
#define _AES_GCM_H_
#include "emp-tool/emp-tool.h"
#include "utils.h"
using namespace emp;

static block R = makeBlock(0xe100000000000000, 0x00);
const string circuit_file_location =
  macro_xstr(EMP_CIRCUIT_PATH) + string("bristol_fashion/");
static BristolFashion aes =
  BristolFashion((circuit_file_location + "aes_128.txt").c_str());

inline block rsht(block x, size_t i) {
    uint64_t* data = (uint64_t*)&x;
    if (i == 0) {
        return x;
    } else if (i < 64) {
        return makeBlock((data[1] >> i),
                         (data[1] << (64 - i)) ^ (data[0] >> i));
    } else if (i < 128) {
        return makeBlock(0x00, data[1] >> (i - 64));
    } else
        return makeBlock(0x00, 0x00);
}

inline block mulBlock(block x, block y) {
    block Z = zero_block, V = y;

    for (int i = 0; i < 128; i++) {
        Z = getLSB(rsht(x, 127 - i)) ? Z ^ V : Z;
        V = getLSB(V) ? rsht(V, 1) ^ R : rsht(V, 1);
    }
    return Z;
}

inline block ghash(block h, block* x, size_t m) {
    block y = zero_block;
    for (int i = 0; i < m; i++) {
        y = mulBlock((y ^ x[i]), h);
    }
    return y;
}
class AES_GCM {
   public:
    Integer key;
    Integer H;
    AES_GCM(Integer _key) : key(_key) { H = computeH(); }

    ~AES_GCM() {}

    inline Integer computeH() {
        Integer o;
        Integer zero(128, 0, PUBLIC);
        Bit* in = new Bit[256];
        memcpy(in, key.bits.data(), 128);
        memcpy(in + 128, zero.bits.data(), 128);

        aes.compute(o.bits.data(), in);

        delete[] in;
        return o;
    }

    inline Integer inc(Integer& counter, size_t s) {
        if (counter.size() < s) {
            error("invalid length s!");
        }
        Integer msb = counter, lsb = counter;
        msb.bits.erase(msb.bits.begin(), msb.bits.begin() + s);
        lsb.bits.erase(lsb.bits.begin() + s, lsb.bits.end());
        lsb = lsb + Integer(s, 1, PUBLIC);

        concat(msb, &lsb, 1);
        return msb;
    }

    inline void gctr(Integer& res, Integer& counter, size_t m) {
        Integer tmp;
        Bit* content = new Bit[128];
        memcpy(content, key.bits.data(), 128);
        for (int i = 0; i < m; i++) {
            memcpy(content + 128, counter.bits.data(), 128);
            aes.compute(tmp.bits.data(), content);

            concat(res, &tmp, 1);
            counter = inc(counter, 32);
        }
        delete[] content;
    }

    inline void enc(NetIO* io,
                    unsigned char* ctxt,
                    unsigned char* tag,
                    unsigned char* iv,
                    unsigned char* msg,
                    size_t m,
                    unsigned char* aInfo,
                    size_t info_len,
                    int party) {
        if (sizeof(iv) != 12) {
            error("invalid IV length!");
        }
        reverse(iv, iv + sizeof(iv));
        Integer J(96, iv, PUBLIC);
        Integer ONE = Integer(32, 1, PUBLIC);
        concat(J, &ONE, 1);

        size_t u =
          128 * ((m * 8 + 128 - 1) / 128) - m * 8; // 128 * ceil(8m/128) - 8m
        // size_t v = 128 * ((info_len * 8 + 128 - 1) / 128) - info_len * 8; // 128 *
        // ceil(8*info_len/128) - info_len*8
        size_t ctr_len = (m * 8 + 128 - 1) / 128;

        Integer Z;
        gctr(Z, J, 1 + ctr_len);

        // Integer H = computeH();
        H.bits.insert(H.bits.end(), Z.bits.end() - 128, Z.bits.end());

        block* h_z0 = new block[2];
        H.reveal<block>((block*)h_z0, ALICE);

        Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
        Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

        unsigned char* z = new unsigned char[u / 8];
        Z.reveal<unsigned char>((unsigned char*)z, BOB);

        if (party == ALICE) {
            size_t v = 128 * ((info_len * 8 + 128 - 1) / 128) -
                       info_len * 8; // 128 * ceil(8*info_len/128) - info_len*8

            io->recv_data(ctxt, m);
            unsigned char* x =
              new unsigned char[u / 8 + m + v / 8 + info_len + 16];
            memcpy(x, aInfo, info_len);
            memset(x + info_len, 0, v / 8);
            memcpy(x + info_len + v / 8, ctxt, m);
            memset(x + info_len + v / 8 + m, 0, u / 8);
            memcpy(x + info_len + v / 8 + m + u / 8, (unsigned char*)&info_len,
                   8);
            memcpy(x + info_len + v / 8 + m + u / 8 + 8, (unsigned char*)&m, 8);

            block* xblk = (block*)&x;
            block t =
              ghash(h_z0[0], xblk, (u + 8 * m + v + 8 * info_len) / 128 + 1);
            t = t ^ h_z0[1];
            tag = (unsigned char*)&t;
            io->send_data(tag, 16);
            delete[] x;
        } else if (party == BOB) {
            for (int i = 0; i < m; i++) {
                ctxt[i] = z[i] ^ msg[i];
            }
            io->send_data(ctxt, m);
            io->recv_data(tag, 16);
        }

        delete[] h_z0;
        delete[] z;
    }

    // inline void dec(NetIO* io, unsigned char* msg, unsigned char* ctxt, size_t m, unsigned char*
    // tag, unsigned char* iv, unsigned char* aInfo, size_t info_len, int party) {
    //     if (sizeof(iv) != 12) {
    //         error("invalid IV length!");
    //     }
    //     reverse(iv, iv + sizeof(iv));

    //     Integer J(96, iv, PUBLIC);
    //     Integer ONE = Integer(32, 1, PUBLIC);
    //     concat(J, &ONE, 1);

    //     size_t u = 128 * ((m * 8 + 128 - 1) / 128) - m * 8; // 128 * ceil(8m/128) -8m
    //     size_t v = 128 * ((info_len * 8 + 128 - 1) / 128) - info_len * 8; // 128*
    //     ceil(8*info_len/128)-info_len*8 size_t ctr_len = (m * 8 + 128 - 1) / 128;

    //     Integer Z;
    //     gctr(Z, J, 1 + ctr_len);

    //     Integer H = computeH();
    //     H.bits.insert(H.bits.end(), Z.bits.end() - 128, Z.bits.end());

    //     block* h_z0 = new block[2];
    //     H.reveal<block>((block*)h_z0, ALICE);

    //     Z.bits.erase(Z.bits.end() - 128, Z.bits.end());
    //     Z.bits.erase(Z.bits.begin(), Z.bits.begin() + u);

    //     unsigned char* z = new unsigned char[u / 8];
    //     Z.reveal<unsigned char>((unsigned char*)z, BOB);
    // }
};
#endif