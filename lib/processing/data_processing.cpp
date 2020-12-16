#include "data_processing.h"
#include "examples.h"

void query_computations(PublicKey db_pubkey,SecretKey db_seckey,Ciphertext** cypher,Ciphertext** bitM,int lines,int columns){
    query_sum(cypher,bitM,lines,columns,3,0,1,1);
    Ciphertext* returner=new Ciphertext[lines];
    query_find(cypher,bitM,lines,columns,5,0,1,returner);
    delete[] returner;
}

void query_sum(Ciphertext** cypher,Ciphertext** bitM,int lines,int columns,int target,int target_search,int target_add,int pick_bit){
    int sum,buffer,line,column;
    Plaintext buffer_decrypted;
    Ciphertext* bit_saver;
    ifstream parms_file;
    ifstream pb_file;
    ifstream sec_file;
    ifstream rel_file;
    PublicKey db_pubkey;
    SecretKey db_seckey;
    RelinKeys relin_keys;


    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados

    parms_file.open("lib/assets/certificates/database/parms.pem",ios::binary);
    parms.load(parms_file);
    parms_file.close();

    pb_file.open("lib/assets/certificates/database/db_pbkey.key",ios::binary);
    sec_file.open("lib/assets/certificates/database/db_sckey.key",ios::binary);
    rel_file.open("lib/assets/certificates/database/db_relkey.key",ios::binary);

    //contexto e validacao
    SEALContext context(parms);

    if(pb_file.is_open()){
        db_pubkey.load(context,pb_file);
        pb_file.close();
    }
    if(sec_file.is_open()){
        db_seckey.load(context,sec_file);
        sec_file.close();
    }
    if(rel_file.is_open()){
        relin_keys.load(context,rel_file);
        rel_file.close();
    }

    //encriptacao usando public
    Encryptor encryptor(context, db_pubkey);

    Decryptor decryptor(context, db_seckey);

    //computacao no ciphertext
    Evaluator evaluator(context);

    sum=0;
    Plaintext plain_sum(to_string(sum));
    Ciphertext sum_encrypted_single;
    encryptor.encrypt(plain_sum,sum_encrypted_single);

    //SELECT SUM(Height) FROM example_table WHERE Age = 𝐻(23)
    buffer=target;
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

    for(int i=0;i<lines;i++){
        int holder;
        int bit_line=(i+1)*columns-(columns-target_search);
        Ciphertext Comp_holder;
        cout << "Linha de bits e " << bit_line << endl;
        Comp_holder=compare_cyphers(bit_saver,bitM,bit_line,pick_bit);

        cout << "Diz que " << i << " e:" << endl;
        decryptor.decrypt(Comp_holder, buffer_decrypted);
        sscanf(buffer_decrypted.to_string().c_str(),"%x",&holder);
        cout << "Verdadeiro ou falso: " << holder << endl;

        cout << "Pre-soma" << endl;
        evaluator.multiply_inplace(Comp_holder,cypher[i][target_add]);

        decryptor.decrypt(Comp_holder, buffer_decrypted);
        sscanf(buffer_decrypted.to_string().c_str(),"%x",&holder);
        cout << "Multiplicacao pelo numero: " << holder << endl;

        evaluator.relinearize_inplace(Comp_holder, relin_keys);
        evaluator.add_inplace(sum_encrypted_single,Comp_holder);

        decryptor.decrypt(sum_encrypted_single, buffer_decrypted);
        sscanf(buffer_decrypted.to_string().c_str(),"%x",&holder);
        cout << "Sum iteration " << i <<" is: " << holder << endl;
    }
    delete[] bit_saver;

    //decriptacao usando private
    decryptor.decrypt(sum_encrypted_single, buffer_decrypted);
    sscanf(buffer_decrypted.to_string().c_str(),"%x",&sum);
    cout << "Sum is: " << sum << endl;
    cout << "  SOMATORIO  + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(sum_encrypted_single) << " bits" << endl;

}

void query_find(Ciphertext** cypher,Ciphertext** bitM,int lines,int columns,int target,int target_search,int pick_bit,Ciphertext* returner){
    int sum,buffer,line,column;
    Plaintext buffer_decrypted;
    Ciphertext* bit_saver;
    ifstream parms_file;
    ifstream pb_file;
    ifstream sec_file;
    ifstream rel_file;
    PublicKey db_pubkey;
    SecretKey db_seckey;
    RelinKeys relin_keys;


    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados

    parms_file.open("lib/assets/certificates/database/parms.pem",ios::binary);
    parms.load(parms_file);
    parms_file.close();

    pb_file.open("lib/assets/certificates/database/db_pbkey.key",ios::binary);
    sec_file.open("lib/assets/certificates/database/db_sckey.key",ios::binary);
    rel_file.open("lib/assets/certificates/database/db_relkey.key",ios::binary);

    //contexto e validacao
    SEALContext context(parms);

    if(pb_file.is_open()){
        db_pubkey.load(context,pb_file);
        pb_file.close();
    }
    if(sec_file.is_open()){
        db_seckey.load(context,sec_file);
        sec_file.close();
    }
    if(rel_file.is_open()){
        relin_keys.load(context,rel_file);
        rel_file.close();
    }

    //encriptacao usando public
    Encryptor encryptor(context, db_pubkey);

    Decryptor decryptor(context, db_seckey);

    //computacao no ciphertext
    Evaluator evaluator(context);

    sum=0;
    Plaintext plain_sum(to_string(sum));
    Ciphertext sum_encrypted_single;
    encryptor.encrypt(plain_sum,sum_encrypted_single);

    //SELECT SUM(Height) FROM example_table WHERE Age = 𝐻(23)
    buffer=target;
    std::stringstream hexstream (ios_base::out);
    hexstream << std::hex << buffer;
    Plaintext plain_buffer(hexstream.str());
    Ciphertext buffer_encrypted;
    std::string input_bin = std::bitset<8>(buffer).to_string();
    std::cout<<input_bin<<"<-Binario do " << buffer << endl;
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

    for(int i=0;i<lines;i++){
        int holder;
        int bit_line=(i+1)*columns-(columns-target_search);
        Ciphertext Comp_holder;
        cout << "Linha de bits e " << bit_line << endl;
        Comp_holder=compare_cyphers(bit_saver,bitM,bit_line,pick_bit);

        cout << "Diz que " << i << " e:" << endl;
        decryptor.decrypt(Comp_holder, buffer_decrypted);
        sscanf(buffer_decrypted.to_string().c_str(),"%x",&holder);
        cout << "Verdadeiro ou falso: " << holder << endl;

        returner[i]=Comp_holder;
    }
    delete[] bit_saver;
}

Ciphertext Mult(Ciphertext cypherA,Ciphertext cypherB){
    PublicKey db_pubkey;
    SecretKey db_seckey;
    RelinKeys relin_keys;

    ifstream parms_file;
    ifstream pb_file;
    ifstream sec_file;
    ifstream rel_file;

    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados

    parms_file.open("lib/assets/certificates/database/parms.pem",ios::binary);
    parms.load(parms_file);
    parms_file.close();

    pb_file.open("lib/assets/certificates/database/db_pbkey.key",ios::binary);
    sec_file.open("lib/assets/certificates/database/db_sckey.key",ios::binary);
    rel_file.open("lib/assets/certificates/database/db_relkey.key",ios::binary);


    //contexto e validacao
    SEALContext context(parms);

    if(pb_file.is_open()){
        db_pubkey.load(context,pb_file);
        pb_file.close();
    }
    if(sec_file.is_open()){
        db_seckey.load(context,sec_file);
        sec_file.close();
    }
    if(rel_file.is_open()){
        relin_keys.load(context,rel_file);
        rel_file.close();
    }

    //encriptacao usando public
    Encryptor encryptor(context, db_pubkey);

    //decriptacao usando private
    Decryptor decryptor(context, db_seckey);

    //computacao no ciphertext
    Evaluator evaluator(context);

    cout << "       Entra no And os bits:" << endl;
    //decriptacao usando private
    int sum;
    Plaintext buffer_decrypted;
    decryptor.decrypt(cypherA, buffer_decrypted);
    sscanf(buffer_decrypted.to_string().c_str(),"%x",&sum);
    cout << "        Entrada A is: " << sum << endl;

    decryptor.decrypt(cypherB, buffer_decrypted);
    sscanf(buffer_decrypted.to_string().c_str(),"%x",&sum);
    cout << "        Entrada B is: " << sum << endl;

    //cout << "  Inicio  + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(cypherA) << " bits" << endl;
    evaluator.multiply_inplace(cypherA,cypherB);
    evaluator.relinearize_inplace(cypherA, relin_keys);
    //cout << "  Iteration  + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(cypherA) << " bits" << endl;

    //decriptacao usando private
    //int sum;
    //Plaintext buffer_decrypted;
    decryptor.decrypt(cypherA, buffer_decrypted);
    sscanf(buffer_decrypted.to_string().c_str(),"%x",&sum);
    cout << "Mult is: " << sum << endl;

    return cypherA;
}

Ciphertext compare_cyphers(Ciphertext* cypherA,Ciphertext** cypherB,int line,int pick_bit){
    Ciphertext* flow;
    Ciphertext holder;
    int zero=0,one=1;
    PublicKey db_pubkey;
    ifstream parms_file;
    ifstream pb_file;

    SecretKey db_seckey;
    ifstream sec_file;
    sec_file.open("lib/assets/certificates/database/db_sckey.key",ios::binary);


    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados

    parms_file.open("lib/assets/certificates/database/parms.pem",ios::binary);
    parms.load(parms_file);
    parms_file.close();

    pb_file.open("lib/assets/certificates/database/db_pbkey.key",ios::binary);

    //contexto e validacao
    SEALContext context(parms);

    if(pb_file.is_open()){
        db_pubkey.load(context,pb_file);
        pb_file.close();
    }
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

    Plaintext plain_zero(to_string(zero));
    Ciphertext zero_encrypted;
    encryptor.encrypt(plain_zero,zero_encrypted);

    Plaintext plain_one(to_string(one));
    Ciphertext one_encrypted;
    encryptor.encrypt(plain_one,one_encrypted);

    flow=new Ciphertext[3];
    flow[0]=zero_encrypted;
    flow[1]=one_encrypted;
    flow[2]=zero_encrypted;

    for(int i=0;i<8;i++){
        Plaintext plain_zero(to_string(zero));
        Ciphertext zero_encrypted;
        encryptor.encrypt(plain_zero,zero_encrypted);

        Plaintext plain_one(to_string(one));
        Ciphertext one_encrypted;
        encryptor.encrypt(plain_one,one_encrypted);

        cout << "ITERATION                                                   " << i << endl;
        comparator(cypherA[i],cypherB[line][i],flow,zero_encrypted,one_encrypted);
        for(int k=0;k<3;k++){
            int sum;
            Plaintext buffer_decrypted;
            decryptor.decrypt(flow[k], buffer_decrypted);
            sscanf(buffer_decrypted.to_string().c_str(),"%x",&sum);
            cout << "Flow " << k << " is: " << sum << endl;
        }
    }

    holder=flow[pick_bit];
    delete[] flow;
    return holder;
}

void comparator(Ciphertext A,Ciphertext B,Ciphertext* flow,Ciphertext zero,Ciphertext one){
    Ciphertext* flowz;
    flowz=new Ciphertext[3];
    flowz[0]=flow[0];
    flowz[1]=flow[1];
    flowz[2]=flow[2];

    cout << "Ab" << endl;
    Ciphertext Ab=Mult(A,not_logic(B,one));
    cout << "aB" << endl;
    Ciphertext aB=Mult(not_logic(A,one),B);
    cout << "ab" << endl;
    Ciphertext ab=Mult(not_logic(A,one),not_logic(B,one));
    cout << "AB" << endl;
    Ciphertext AB=Mult(A,B);

    cout << "                             Flow 0:" << endl;
    flow[0]=not_logic(and_logic(not_logic(flowz[0],one),not_logic(and_logic(Ab,flowz[1]),one)),one);
    cout << "                             Flow 1:" << endl;
    flow[1]=not_logic(and_logic(not_logic(and_logic(ab,flowz[1]),one),not_logic(and_logic(AB,flowz[1]),one)),one);
    cout << "                             Flow 2:" << endl;
    flow[2]=not_logic(and_logic(not_logic(flowz[2],one),not_logic(and_logic(aB,flowz[1]),one)),one);
    delete[] flowz;
 }

Ciphertext and_logic(Ciphertext bit1,Ciphertext bit2){
    bit2=Mult(bit1,bit2);
    return bit2;
}

Ciphertext not_logic(Ciphertext bit,Ciphertext one){
    ifstream parms_file;

    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados
    parms_file.open("lib/assets/certificates/database/parms.pem",ios::binary);
    parms.load(parms_file);
    parms_file.close();

    //contexto e validacao
    SEALContext context(parms);

    //computacao no ciphertext
    Evaluator evaluator(context);

    evaluator.sub_inplace(one,bit);

    return one;
}