#include <iostream>

#include "main.h"

int main()
{
    int buffer;
    SecretKey db_seckey;
    PublicKey db_pubkey;

    buffer=runTest();

    cout << "Criacao das keys DB\n\n";

    db_key(&db_seckey,&db_pubkey);

    key_confirm(db_seckey,db_pubkey);

    return buffer;
}