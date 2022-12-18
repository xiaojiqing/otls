#ifndef UTILS_H
#define UTILS_H

#include "emp-tool/emp-tool.h"
#include <iostream>
#include <vector>
#include <string>

using namespace std;
using namespace emp;
using std::string;
using std::vector;

inline Integer rrot(const Integer& rhs, int sht) {
    Integer tmp(rhs);
    return (tmp >> sht) ^ (tmp << (tmp.size() - sht));
}

inline Integer lrot(const Integer& rhs, int sht) {
    Integer tmp(rhs);
    return (tmp << sht) ^ (tmp >> (tmp.size() - sht));
}

inline Integer str_to_int(string str, int party) {
    uint64_t mlen = str.length() * 8;
    Integer res = Integer(mlen, 0, PUBLIC);
    std::reverse(str.begin(), str.end());
    for (uint64_t i = 0; i < str.length(); i++) {
        res = res | (Integer(mlen, (int)str[i], party) << (8 * i));
    }
    return res;
}

/*inline vector<Bit> str_to_bits(string str){
	vector<Bit> bits;
	bool b;
	for(uint64_t i = 0; i < str.length(); i++){
		for(int j = sizeof(char)-1; j >= 0; j--){
			b = ((str[i]&(1<<j))==1)? true:false;
			bits.push_back(Bit(b));
		}
	}
		return bits;
}
*/

inline string int_to_hex(vector<uint32_t> vint) {
    string str;
    uint tmp_int;
    char* buffer = new char[3];

    for (uint64_t i = 0; i < vint.size(); i++) {
        for (int j = 3; j >= 0; j--) {
            tmp_int = (vint[i] & (0xFF << (8 * j))) >> (8 * j);
            sprintf(buffer, "%02x", tmp_int);
            str += buffer;
        }
    }
    //	cout<<str.length()<<endl;
    delete[] buffer;

    return str;
}

inline string int_to_hex(vector<uint64_t> vint) {
    string str;
    uint tmp_int;
    char* buffer = new char[3];

    for (uint64_t i = 0; i < vint.size(); i++) {
        for (int j = 7; j >= 0; j--) {
            tmp_int = (vint[i] & (0xFFLL << (8 * j))) >> (8 * j);
            sprintf(buffer, "%02x", tmp_int);
            str += buffer;
        }
    }
    delete[] buffer;

    return str;
}

inline void print_hex_64(Integer* s, int len) {
    vector<uint64_t> outhex;
    uint64_t tmp;
    for (int i = 0; i < len; i++) {
        tmp = s[i].reveal<uint64_t>();
        outhex.push_back(tmp);
    }
    cout << int_to_hex(outhex) << endl;
}

inline void print_hex_32(Integer* s, int len) {
    vector<uint32_t> outhex;
    uint32_t tmp;
    for (int i = 0; i < len; i++) {
        tmp = s[i].reveal<uint32_t>();
        outhex.push_back(tmp);
    }
    cout << int_to_hex(outhex) << endl;
}

inline void intvec_to_int(Integer& out, Integer* in, size_t len) {
    size_t s = in[0].size();
    out = Integer(s * len, 0, PUBLIC);
    Integer tmp = Integer(s * len, 0, PUBLIC);
    for (int i = 0; i < len; i++) {
        in[i].resize(s * len, false);
        out ^= ((tmp ^ in[i]) << ((len - 1 - i) * s));
    }
}
#endif
