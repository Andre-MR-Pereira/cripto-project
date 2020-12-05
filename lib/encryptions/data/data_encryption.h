#include "seal/seal.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>


using namespace std;
using namespace seal;

void data_encryption(PublicKey,int**,Ciphertext**);
void data_decryption(SecretKey,Ciphertext**);
void query_computations(PublicKey,SecretKey,Ciphertext**);
//void help_function(const std::vector<seal::Ciphertext*> ,Evaluator);
void test_data(int** &,Ciphertext** &);
void test_destructor(int**,Ciphertext**);