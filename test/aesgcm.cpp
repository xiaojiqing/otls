#include "emp-tool/emp-tool.h"
#include "prf/aesgcm.h"
#include <iostream>

using namespace emp;
using namespace std;
void mul_test() {
    block H = makeBlock(0x0388DACE60B6A392, 0xF328C2B971B2FE78);
    block C = makeBlock(0x66E94BD4EF8A2C3B, 0x884CFA59CA342B2E);
    block HC = makeBlock(0x5E2EC74691706288, 0x2C85B0685353DEB7);

    block HC1 = mulBlock(H, C);
    block HC2 = mulBlock(C, H);
    cout << "HC1: " << HC1 << endl;
    cout << "HC2: " << HC2 << endl;
    cout << "expected HC: " << HC << endl;

}

int main() { mul_test(); }