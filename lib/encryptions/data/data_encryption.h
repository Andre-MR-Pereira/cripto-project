#include "seal/seal.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>
#include <string>
#include <sstream>

using namespace std;
using namespace seal;

void data_encryption(int**,Ciphertext**,Ciphertext**,int,int);
void data_decryption(Ciphertext**,Ciphertext**,int,int);
void test_data(int** &,Ciphertext** &,Ciphertext** &);
void test_destructor(int**,Ciphertext**,Ciphertext**);