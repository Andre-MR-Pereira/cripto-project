#include "data_encryption.h"

void data_encryption(PublicKey db_pubkey,int** data,Ciphertext** cypher){
    int buffer;
    ofstream file;
    ifstream parms_file;

    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados

    parms_file.open("lib/assets/certificates/database/parms.pem",ios::binary);
    parms.load(parms_file);
    parms_file.close();

    //contexto e validacao
    SEALContext context(parms);

    //encriptacao usando public
    Encryptor encryptor(context, db_pubkey);

    //computacao no ciphertext
    Evaluator evaluator(context);

    file.open("lib/assets/certificates/database/data.bin",ios::binary);
    for(int i=0;i<11;i++){
        for(int j=0;j<3;j++){
            buffer=data[i][j];
            Plaintext plain_buffer(to_string(buffer));
            Ciphertext buffer_encrypted;
            std::string input_bin = std::bitset<32>(buffer).to_string();
            std::cout<<input_bin<<"<-Binario\n";
            encryptor.encrypt(plain_buffer,buffer_encrypted);
            cypher[i][j]=buffer_encrypted;
            file << buffer_encrypted.save_size() << " ";
            buffer_encrypted.save(file);
            for(int k=0;k<32;k++){
                Plaintext x_plain_bin(input_bin[k]);
                Ciphertext x_encrypted_bin;
                encryptor.encrypt(x_plain_bin, x_encrypted_bin);
                file << " " << x_encrypted_bin.save_size() << " ";
                x_encrypted_bin.save(file);
            }
        }
        file << "\n";
    }
    file.close();
}

void data_decryption(SecretKey db_seckey,Ciphertext** cypher){
    Plaintext buffer_decrypted;
    Plaintext data_decrypted;
    Plaintext bytesize_decrypted;

    ifstream parms_file;
    ifstream data_file;

    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados

    parms_file.open("lib/assets/certificates/database/parms.pem",ios::binary);
    parms.load(parms_file);
    parms_file.close();

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

    /*data_file.open("lib/assets/certificates/database/data.bin",ios::binary);
    for(int i=0;i<11;i++){
        for(int j=0;j<3;j++){
            decryptor.decrypt(cypher[i][j], bytesize_decrypted);
        }
    }
    data_file.close();*/

}

void query_computations(PublicKey db_pubkey,SecretKey db_seckey,Ciphertext** cypher){
    int buffer;
    int sum;
    Plaintext buffer_decrypted;
    Ciphertext* saver;

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

    buffer=23;
    sum=0;
    Plaintext plain_buffer(to_string(buffer));
    Plaintext plain_sum(to_string(sum));
    Ciphertext buffer_encrypted;
    Ciphertext sum_encrypted_single;
    encryptor.encrypt(plain_buffer,buffer_encrypted);
    encryptor.encrypt(plain_sum,sum_encrypted_single);
    saver = new Ciphertext[11];
    //SELECT SUM(Height) FROM example_table WHERE Age = 𝐻(23)
    //considerar usar add_many quando estiver na query
    for(int i=0;i<1;i++){
        /*if(cypher[i][0]==buffer_encrypted){    //coluna 0 e a age
            evaluator.add(sum_encrypted,cypher[i][0],sum_encrypted);
        }*/
        evaluator.add(sum_encrypted_single,cypher[i][1],sum_encrypted_single);
        saver[i]=cypher[i][1];
    }
    //help_function(saver,evaluator);
    //decriptacao usando private
    Decryptor decryptor(context, db_seckey);

    decryptor.decrypt(sum_encrypted_single, buffer_decrypted);
    cout << "Single is: " << buffer_decrypted.to_string() << " \n" << endl;
}

/*void help_function(const std::vector<seal::Ciphertext*> saver,Evaluator evaluator){
    Ciphertext sum_encrypted_all;
    Ciphertext buffer_encrypted;

    evaluator.add_many(saver,sum_encrypted_all);
    decryptor.decrypt(sum_encrypted_all, buffer_decrypted);
    cout << "All is: " << buffer_decrypted.to_string() << " \n" << endl;
}*/

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