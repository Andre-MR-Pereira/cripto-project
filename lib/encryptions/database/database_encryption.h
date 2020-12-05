#include "seal/seal.h"
#include <iostream>
#include <fstream>
#include <bitset>

using namespace std;
using namespace seal;

void db_key(SecretKey *,PublicKey *);
void key_confirm(SecretKey,PublicKey);
void binary_encryption(int,Encryptor,Decryptor);
void binary_decryption(Ciphertext,Decryptor);