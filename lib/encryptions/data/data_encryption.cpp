#include "data_encryption.h"

void data_encryption(int** data,Ciphertext** cypher,Ciphertext** bitM,int lines,int columns){
    int buffer;
    int holder;
    ofstream file;
    ifstream parms_file;
    ifstream pb_file;
    int line=0;
    PublicKey db_pubkey;
    //
    SecretKey db_seckey;
    ifstream sec_file;

    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados

    parms_file.open("lib/assets/certificates/database/parms.pem",ios::binary);
    parms.load(parms_file);
    parms_file.close();

    pb_file.open("lib/assets/certificates/database/db_pbkey.key",ios::binary);
    //
    sec_file.open("lib/assets/certificates/database/db_sckey.key",ios::binary);

    //contexto e validacao
    SEALContext context(parms);

    if(pb_file.is_open()){
        db_pubkey.load(context,pb_file);
        pb_file.close();
    }
    //
    if(sec_file.is_open()){
        db_seckey.load(context,sec_file);
        sec_file.close();
    }

    //encriptacao usando public
    Encryptor encryptor(context, db_pubkey);

    //decriptacao usando private
    Decryptor decryptor(context, db_seckey);

    //computacao no ciphertext
    Evaluator evaluator(context);

    file.open("lib/assets/certificates/database/data.bin",ios::binary);

    for(int i=0;i<lines;i++){
        for(int j=0;j<columns;j++){
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
                if(input_bin[k]=='0'){
                    x=0;
                }else{
                    x=1;
                }
                Plaintext x_plain_bin(to_string(x));
                Ciphertext x_encrypted_bin;
                encryptor.encrypt(x_plain_bin, x_encrypted_bin);
                //cout << "guarda" << endl;
                bitM[line][k]=x_encrypted_bin;
                //cout << "passa" << endl;
                file << x_encrypted_bin.save_size();
                x_encrypted_bin.save(file);
                //cout << "  Inicio  + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(bitM[line][k]) << " bits" << endl;
            }
            line++;
        }
    }
    file.close();
}

void data_decryption(Ciphertext** cypher,Ciphertext** bitM,int lines,int columns){
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
    SecretKey db_seckey;

    ifstream parms_file;
    ifstream data_file;
    ifstream sec_file;

    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados

    parms_file.open("lib/assets/certificates/database/parms.pem",ios::binary);
    parms.load(parms_file);
    parms_file.close();

    sec_file.open("lib/assets/certificates/database/db_sckey.key",ios::binary);

    //contexto e validacao
    SEALContext context(parms);

    if(sec_file.is_open()){
        db_seckey.load(context,sec_file);
        sec_file.close();
    }

    //computacao no ciphertext
    Evaluator evaluator(context);

    //decriptacao usando private
    Decryptor decryptor(context, db_seckey);

    data_file.open("lib/assets/certificates/database/data.bin",ios::in | ios::binary);
    if(data_file.is_open()){
        for(int i=0;i<lines;i++){
            for(int j=0;j<columns;j++){
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

void test_data(int** &data,Ciphertext** &cypher,Ciphertext** &bitM) {
    int data_test[11][3] = {     //age,height,awards
            {3, 5, 3} ,
            {3, 5, 4} ,
            {1, 2, 5} ,
            {5, 2, 3} ,
            {1, 2, 4} ,
            {5, 2, 5} ,
            {4, 2, 3} ,
            {1, 2, 4} ,
            {4, 2, 5} ,
            {2, 2, 3} ,
            {3, 2, 4} ,
    };

    data = new int*[11];
    cypher = new Ciphertext*[11];
    bitM = new Ciphertext*[33];
    for(int i=0;i<11;i++){
        data[i]=new int[3];
        cypher[i]=new Ciphertext[3];
    }
    for(int i=0;i<33;i++){
        bitM[i]=new Ciphertext[8];
    }
    for(int i=0;i<11;i++){
        for(int j=0;j<3;j++){
            data[i][j]=data_test[i][j];
        }
    }
}

void test_destructor(int** test,Ciphertext** cypher,Ciphertext** bitM) {
    for(int i=0;i<11;i++){
        delete[] test[i];
        delete[] cypher[i];
    }
    for(int i=0;i<33;i++){
        delete[] bitM[i];
    }
    delete[] test;
    delete[] cypher;
    delete[] bitM;
}