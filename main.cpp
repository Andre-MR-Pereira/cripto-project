#include <iostream>

#include "main.h"

int main()
{
    int buffer;
    SecretKey db_seckey;
    PublicKey db_pubkey;
    int** data=nullptr;
    Ciphertext** cypher;

    //buffer=runTest();

    cout << "Criacao das keys DB\n\n";

    db_key(&db_seckey,&db_pubkey);

    file_output(db_pubkey,db_seckey);

    //key_confirm(db_seckey,db_pubkey);

    cout << "Start:\n\n";

    test_data(data,cypher);

    data_encryption(db_pubkey,data,cypher);

    query_computations(db_pubkey,db_seckey,cypher);

    data_decryption(db_seckey,cypher);

    test_destructor(data,cypher);

    return buffer;
}