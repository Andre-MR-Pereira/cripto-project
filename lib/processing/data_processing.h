#include "seal/seal.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>
#include <string>
#include <sstream>

using namespace std;
using namespace seal;

void query_computations(PublicKey,SecretKey,Ciphertext**,Ciphertext**);
void query_sum(Ciphertext**,Ciphertext**);
Ciphertext Mult(Ciphertext,Ciphertext);
Ciphertext compare_cyphers(Ciphertext*,Ciphertext**,int);
void comparator(Ciphertext,Ciphertext,Ciphertext*,Ciphertext,Ciphertext);
Ciphertext and_logic(Ciphertext,Ciphertext,Ciphertext);
Ciphertext not_logic(Ciphertext,Ciphertext);