#include "data_encryption.h"

void data_encryption(PublicKey db_pubkey,int** data,Ciphertext** cypher){
    int buffer;

    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados

    //parametros
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(1024);

    //contexto e validacao
    SEALContext context(parms);

    //encriptacao usando public
    Encryptor encryptor(context, db_pubkey);

    //computacao no ciphertext
    Evaluator evaluator(context);


    for(int i=0;i<11;i++){
        for(int j=0;j<3;j++){
            buffer=data[i][j];
            Plaintext plain_buffer(to_string(buffer));
            Ciphertext buffer_encrypted;
            encryptor.encrypt(plain_buffer,buffer_encrypted);
            cypher[i][j]=buffer_encrypted;
        }
    }
}

void data_decryption(SecretKey db_seckey,Ciphertext** cypher){
    Plaintext buffer_decrypted;

    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados

    //parametros
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(1024);

    //contexto e validacao
    SEALContext context(parms);

    //computacao no ciphertext
    Evaluator evaluator(context);

    //decriptacao usando private
    Decryptor decryptor(context, db_seckey);

    for(int i=0;i<11;i++){
        for(int j=0;j<3;j++){
            decryptor.decrypt(cypher[i][j], buffer_decrypted);
            cout << "Value is: " << buffer_decrypted.to_string() << " \n" << endl;
        }
    }
}

void test_data(int** &data,Ciphertext** &cypher) {
    int data_test[11][3] = {     //age,height,awards
            {23, 172, 3} ,
            {45, 171, 3} ,
            {34, 167, 3} ,
            {23, 180, 4} ,
            {34, 172, 4} ,
            {20, 200, 3} ,
            {45, 178, 4} ,
            {34, 172, 4} ,
            {34, 173, 3} ,
            {25, 201, 3} ,
            {34, 175, 5} ,
    };

    data = new int*[11];
    cypher = new Ciphertext*[11];
    for(int i=0;i<11;i++){
        data[i]=new int[3];
        cypher[i]=new Ciphertext[3];
    }
    for(int i=0;i<11;i++){
        for(int j=0;j<3;j++){
            data[i][j]=data_test[i][j];
        }
    }
}

void test_destructor(int** test,Ciphertext** cypher) {
    for(int i=0;i<11;i++){
        delete[] test[i];
        delete[] cypher[i];
    }
    delete[] test;
    delete[] cypher;
}