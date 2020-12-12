#include "data_processing.h"
#include "examples.h"

void query_computations(PublicKey db_pubkey,SecretKey db_seckey,Ciphertext** cypher,Ciphertext** bitM){
    query_sum(cypher,bitM);
}

void query_sum(Ciphertext** cypher,Ciphertext** bitM){
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
    /*cout << "comeca" << endl;
    Comp_holder=compare_cyphers(bit_saver,bitM,0);
    Decryptor decryptor(context, db_seckey);
    decryptor.decrypt(Comp_holder, buffer_decrypted);
    sscanf(buffer_decrypted.to_string().c_str(),"%x",&sum);
    cout << "Sum is: " << sum << endl;*/

    for(int i=0;i<3;i++){
        line=i/3;
        column=i%3;
        //int x=1;
        //Plaintext plain(to_string(x));
        Ciphertext Comp_holder;
        //encryptor.encrypt(plain,Comp_holder);
        Comp_holder=compare_cyphers(bit_saver,bitM,i);

        cout << "Diz que " << i << " e:" << endl;
        decryptor.decrypt(Comp_holder, buffer_decrypted);
        sscanf(buffer_decrypted.to_string().c_str(),"%x",&sum);
        cout << "Verdadeiro ou falso: " << sum << endl;

        evaluator.multiply_inplace(Comp_holder,cypher[line][column]);
        evaluator.relinearize_inplace(Comp_holder, relin_keys);
        evaluator.add_inplace(sum_encrypted_single,Comp_holder);
    }
    delete[] bit_saver;

    //decriptacao usando private
    decryptor.decrypt(sum_encrypted_single, buffer_decrypted);
    sscanf(buffer_decrypted.to_string().c_str(),"%x",&sum);
    cout << "Sum is: " << sum << endl;
    cout << "  SOMATORIO  + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(sum_encrypted_single) << " bits" << endl;

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

    //cout << "  Inicio  + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(cypherA) << " bits" << endl;
    evaluator.multiply_inplace(cypherA,cypherB);
    evaluator.relinearize_inplace(cypherA, relin_keys);
    //cout << "  Iteration  + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(cypherA) << " bits" << endl;

    //decriptacao usando private
    int sum;
    Plaintext buffer_decrypted;
    decryptor.decrypt(cypherA, buffer_decrypted);
    sscanf(buffer_decrypted.to_string().c_str(),"%x",&sum);
    cout << "Mult is: " << sum << endl;

    return cypherA;
}

Ciphertext compare_cyphers(Ciphertext* cypherA,Ciphertext** cypherB,int line){
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

    flow=new Ciphertext[3];
    flow[0]=zero_encrypted;
    flow[1]=zero_encrypted;
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

    holder=flow[1];
    delete[] flow;
    return holder;
}

void comparator(Ciphertext A,Ciphertext B,Ciphertext* flow,Ciphertext zero,Ciphertext one){
    cout << "Ab" << endl;
    Ciphertext Ab=Mult(A,not_logic(B,one));
    cout << "aB" << endl;
    Ciphertext aB=Mult(not_logic(A,one),B);
    cout << "ab" << endl;
    Ciphertext ab=Mult(not_logic(A,one),not_logic(B,one));
    cout << "AB" << endl;
    Ciphertext AB=Mult(A,B);
    cout << "iIi" << endl;
    Ciphertext iIi=Mult(not_logic(flow[0],one),Mult(flow[1],not_logic(flow[2],one)));
    cout << "iii" << endl;
    Ciphertext iii=Mult(not_logic(flow[0],one),Mult(not_logic(flow[1],one),not_logic(flow[2],one)));

    cout << "                             Flow 0:" << endl;
    flow[0]=not_logic(and_logic(not_logic(flow[0],one),not_logic(Mult(Ab,iIi),one),not_logic(Mult(Ab,iii),one)),one);
    cout << "                             Flow 1:" << endl;
    flow[1]=not_logic(Mult(and_logic(not_logic(Mult(ab,iIi),one),not_logic(Mult(AB,iIi),one),not_logic(Mult(ab,iii),one)),not_logic(Mult(AB,iii),one)),one);
    cout << "                             Flow 2:" << endl;
    flow[2]=not_logic(and_logic(not_logic(flow[2],one),not_logic(Mult(aB,iIi),one),not_logic(Mult(aB,iii),one)),one);

 }

Ciphertext and_logic(Ciphertext bit1,Ciphertext bit2,Ciphertext bit3){
    cout << "ENTRA NO AND!!!!!" << endl;
    bit2=Mult(bit1,bit2);
    bit3=Mult(bit1,bit3);
    cout << "SAI DO AND!!!!!!!" << endl;

    return bit3;
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