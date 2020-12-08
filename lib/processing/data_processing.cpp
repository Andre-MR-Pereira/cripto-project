#include "data_processing.h"

void query_computations(PublicKey db_pubkey,SecretKey db_seckey,Ciphertext** cypher,Ciphertext** bitM){
    query_sum(db_pubkey,db_seckey,cypher,bitM);
    //query_mult(db_pubkey,db_seckey,cypher,bitM);
    cout << compare_cyphers(bitM[0][0],bitM[0][0]) << endl;
}

void query_sum(PublicKey db_pubkey,SecretKey db_seckey,Ciphertext** cypher,Ciphertext** bitM){
    int sum,buffer,division,surplus;
    Plaintext buffer_decrypted;
    Ciphertext* bit_saver;
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

    sum=0;
    Plaintext plain_sum(to_string(sum));
    Ciphertext sum_encrypted_single;
    encryptor.encrypt(plain_sum,sum_encrypted_single);
    //SELECT SUM(Height) FROM example_table WHERE Age = 𝐻(23)
    buffer=23;
    std::stringstream hexstream (ios_base::out);
    hexstream << std::hex << buffer;
    Plaintext plain_buffer(hexstream.str());
    Ciphertext buffer_encrypted;
    std::string input_bin = std::bitset<8>(buffer).to_string();
    std::cout<<input_bin<<"<-Binario do 23" << endl;
    encryptor.encrypt(plain_buffer,buffer_encrypted);
    bit_saver = new Ciphertext[8];
    for(int k=0;k<8;k++){
        int x;
        if (input_bin[k] == '0') {
            x = 0;
        } else {
            x = 1;
        }
        Plaintext x_plain_bin(to_string(x));
        encryptor.encrypt(x_plain_bin, bit_saver[k]);
    }
    for(int i=0;i<33;i++){
        int flag=1;
        for(int k=0;k<8;k++){
            if(compare_cyphers(bit_saver[k],bitM[i][k])!=1){
                flag=0;
            }
        }
        if(flag==1){
            division=i/3;
            surplus=i%3;
            evaluator.add_inplace(sum_encrypted_single,cypher[division][surplus]);
        }
    }
    delete[] bit_saver;
    //decriptacao usando private
    Decryptor decryptor(context, db_seckey);
    decryptor.decrypt(sum_encrypted_single, buffer_decrypted);
    sscanf(buffer_decrypted.to_string().c_str(),"%x",&sum);
    cout << "Sum is: " << sum << endl;
}

void query_mult(PublicKey db_pubkey,SecretKey db_seckey,Ciphertext** cypher,Ciphertext** bitM){
    int mult;
    Plaintext buffer_decrypted;
    Ciphertext* saver;
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

    KeyGenerator keygen(context);   //instaciacao das chaves

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    //decriptacao usando private
    Decryptor decryptor(context, db_seckey);

    mult=1;
    Plaintext plain_mult(to_string(mult));
    Ciphertext mult_encrypted_single;
    encryptor.encrypt(plain_mult,mult_encrypted_single);
    //SELECT MULT(Height) FROM example_table WHERE Age = 𝐻(23)
    cout << "  Inicio  + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(mult_encrypted_single) << " bits" << endl;
    for(int i=0;i<2;i++){
        evaluator.multiply_inplace(mult_encrypted_single,cypher[i][0]);
        cout << "size bef:" << mult_encrypted_single.size() << endl;
        evaluator.relinearize_inplace(mult_encrypted_single, relin_keys);
        cout << "size aft:" << mult_encrypted_single.size() << endl;
        cout << "  Iteration  + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(mult_encrypted_single) << " bits" << endl;
    }
    /*evaluator.square(mult_encrypted_single, mult_encrypted_single);
    cout << "    + size of x_squared: " << mult_encrypted_single.size() << endl;
    evaluator.relinearize_inplace(mult_encrypted_single, relin_keys);
    cout << "    + size of x_squared (after relinearization): " << mult_encrypted_single.size() << endl;*/
    decryptor.decrypt(mult_encrypted_single, buffer_decrypted);
    sscanf(buffer_decrypted.to_string().c_str(),"%x",&mult);
    cout << "Single is: " << mult << endl;
    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(mult_encrypted_single) << " bits" << endl;
}

int compare_cyphers(Ciphertext cypher1,Ciphertext cypher2){
    int* flow;
    int returner=0;

    flow=new int[3];
    flow[0]=0;
    flow[1]=0;
    flow[2]=0;
    for(int i=0;i<16383;i++){
        //cout << "Compara:" << cypher1[i] << cypher2[i] << flow[0] << flow[1] << flow[2] << endl;
        comparator(cypher1[i],cypher2[i],flow);
        if(flow[0]==1 || flow[2]==1)
            break;
    }
    if(flow[1]==1){
        returner=1;
    }else if(flow[2]==1){
        returner=2;
    }
    delete[] flow;
    return returner;
}

void comparator(int A,int B,int* flow){
    if(not_logic(and_logic(not_logic(flow[0]),not_logic(and_logic(A,not_logic(B),not_logic(flow[0]),flow[1],not_logic(flow[2]))),not_logic(and_logic(A,not_logic(B),not_logic(flow[0]),not_logic(flow[1]),not_logic(flow[2]))),1,1))==1){
        flow[0]=1;
        flow[1]=0;
        flow[2]=0;
    }else if(not_logic(and_logic(not_logic(flow[2]),not_logic(and_logic(not_logic(A),B,not_logic(flow[0]),flow[1],not_logic(flow[2]))),not_logic(and_logic(not_logic(A),B,not_logic(flow[0]),not_logic(flow[1]),not_logic(flow[2]))),1,1))==1){
        flow[0]=0;
        flow[1]=0;
        flow[2]=1;
    }else if(not_logic(and_logic(not_logic(and_logic(not_logic(A),not_logic(B),not_logic(flow[0]),flow[1],not_logic(flow[2]))),not_logic(and_logic(A,B,not_logic(flow[0]),flow[1],not_logic(flow[2]))),not_logic(and_logic(not_logic(A),not_logic(B),not_logic(flow[0]),not_logic(flow[1]),not_logic(flow[2]))),not_logic(and_logic(A,B,not_logic(flow[0]),not_logic(flow[1]),not_logic(flow[2]))),1))==1){
        flow[0]=0;
        flow[1]=1;
        flow[2]=0;
    }
}

int and_logic(int bit1,int bit2,int bit3,int bit4,int bit5){
    return bit1*bit2*bit3*bit4*bit5;
}

int not_logic(int bit){
    if(bit==1){
        return 0;
    }else return 1;
}