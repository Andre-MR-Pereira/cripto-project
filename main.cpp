#include <iostream>

#include "main.h"

int main()
{
    int buffer;
    SecretKey db_seckey;
    PublicKey db_pubkey;
    int** data=nullptr;
    Ciphertext** cypher;
    Ciphertext** bitM;

    //buffer=runTest();

    cout << "Criacao das keys DB\n\n";

    db_key(db_seckey,db_pubkey);

    //file_output(db_pubkey,db_seckey);

    //key_confirm(db_seckey,db_pubkey);

    cout << "Start:\n\n";

    test_data(data,cypher,bitM);

    int lines=11;
    int columns=3;

    data_encryption(data,cypher,bitM,lines,columns);

    query_computations(db_pubkey,db_seckey,cypher,bitM,lines,columns);

    data_decryption(cypher,bitM,lines,columns);

    test_destructor(data,cypher,bitM);

    return buffer;
}