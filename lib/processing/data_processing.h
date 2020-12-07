#include "seal/seal.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>
#include <string>

using namespace std;
using namespace seal;

void query_computations(PublicKey,SecretKey,Ciphertext**);
void query_sum(PublicKey,SecretKey,Ciphertext**);