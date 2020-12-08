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
void query_sum(PublicKey,SecretKey,Ciphertext**,Ciphertext**);
void query_mult(PublicKey,SecretKey,Ciphertext**,Ciphertext**);
int compare_cyphers(Ciphertext,Ciphertext);
void comparator(int,int,int*);
int and_logic(int,int,int,int,int);
int not_logic(int);