#include "data_encryption.h"

void data_encryption(PublicKey db_pubkey,int** data,Ciphertext** cypher){
    int buffer;
    int holder;
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
            std::stringstream hexstream (ios_base::out);
            buffer=data[i][j];
            hexstream << std::hex << buffer;
            Plaintext plain_buffer(hexstream.str());
            Ciphertext buffer_encrypted;
            std::string input_bin = std::bitset<8>(buffer).to_string();
            std::cout<<input_bin<<"<-Binario" << endl;
            encryptor.encrypt(plain_buffer,buffer_encrypted);
            cypher[i][j]=buffer_encrypted;
            file << buffer_encrypted.save_size();
            buffer_encrypted.save(file);
            for(int k=0;k<8;k++){
                int x;
                cout << input_bin[k];
                if(input_bin[k]=='0'){
                    x=0;
                }else{
                    x=1;
                }
                Plaintext x_plain_bin(to_string(x));
                Ciphertext x_encrypted_bin;
                encryptor.encrypt(x_plain_bin, x_encrypted_bin);
                file << x_encrypted_bin.save_size();
                x_encrypted_bin.save(file);
            }
            cout << endl;
        }
    }
    file.close();
}

void data_decryption(SecretKey db_seckey,Ciphertext** cypher){
    Plaintext buffer_decrypted;
    Plaintext data_decrypted;
    Plaintext bytesize_decrypted;
    Ciphertext load_buffer;
    char* memblock;
    streampos size;
    int cypher_size;
    char* cypher_buffer;
    char separator;
    std::string frase;
    int sum;

    ifstream parms_file;
    ifstream data_file;
    fstream temp_file;

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

    data_file.open("lib/assets/certificates/database/data.bin",ios::in | ios::binary);
    if(data_file.is_open()){
        for(int i=0;i<11;i++){
            for(int j=0;j<3;j++){
                data_file >> cypher_size;
                load_buffer.load(context,data_file);
                decryptor.decrypt(load_buffer, buffer_decrypted);
                cout << "Value is: " << buffer_decrypted.to_string() << endl;
                for(int k=0;k<8;k++){
                    data_file >> cypher_size;
                    load_buffer.load(context,data_file);
                    decryptor.decrypt(load_buffer, buffer_decrypted);
                    cout << buffer_decrypted.to_string();
                }
                cout << endl;
            }
        }
        data_file.close();
    }
}

void test_data(int** &data,Ciphertext** &cypher) {
    int data_test[11][3] = {     //age,height,awards
            {1, 12, 35} ,
            {2, 14, 40} ,
            {3, 16, 45} ,
            {4, 18, 50} ,
            {5, 20, 55} ,
            {6, 22, 60} ,
            {7, 24, 65} ,
            {8, 26, 70} ,
            {9, 28, 75} ,
            {10, 30, 80} ,
            {11, 32, 85} ,
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