#include "seal/seal.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>
#include <string>
#include <sstream>

using namespace std;
using namespace seal;

void data_encryption(PublicKey,int**,Ciphertext**);
void data_decryption(SecretKey,Ciphertext**);
void test_data(int** &,Ciphertext** &);
void test_destructor(int**,Ciphertext**);