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

inline Integer rrot(const Integer& rhs, int sht) { return (rhs >> sht) ^ (rhs << (rhs.size() - sht)); }

inline uint32_t rrot(const uint32_t& rhs, int sht) { return (rhs >> sht) | (rhs << (32 - sht)); }

inline Integer lrot(const Integer& rhs, int sht) {
    Integer tmp(rhs);
    return (tmp << sht) ^ (tmp >> (tmp.size() - sht));
}

inline Integer str_to_int(string str, int party) {
    uint64_t mlen = str.length() * 8;
    std::reverse(str.begin(), str.end());
    /*
    Integer res = Integer(mlen, 0, PUBLIC);
	for (uint64_t i = 0; i < str.length(); i++) {
        res = res | (Integer(mlen, (int)str[i], party) << (8 * i));
    }*/
	//Xiao: updated!	
	uint8_t * tmp = new uint8_t[str.length()];
    for (uint64_t i = 0; i < str.length(); i++) {
			tmp[i] = (int)str[i];
    }
	 Integer res(mlen, tmp, party); // note that this line could increase roundtrip
	 delete[] tmp;
	 return res;
}

inline void char_to_uint32(uint32_t* res, const char* in, size_t len){
    for(int i = 0; i < len/4; i++){

    }
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
            snprintf(buffer, 3, "%02x", tmp_int);
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
            snprintf(buffer, 3, "%02x", tmp_int);
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

inline void concat(Integer& res, const Integer* in, size_t len) {
    for (int i = 0; i < len; i++)
        res.bits.insert(res.bits.begin(), in[i].bits.begin(), in[i].bits.end());
}

inline void move_concat(Integer& res, const Integer* in, size_t len) {
    for (int i = 0; i < len; i++)
        res.bits.insert(res.bits.begin(), make_move_iterator(in[i].bits.begin()), make_move_iterator(in[i].bits.end()));
}
#endif
