#include "data_processing.h"

void query_computations(PublicKey db_pubkey,SecretKey db_seckey,Ciphertext** cypher){
    query_sum(db_pubkey,db_seckey,cypher);
}

void query_sum(PublicKey db_pubkey,SecretKey db_seckey,Ciphertext** cypher){
    int sum;
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

    sum=0;
    Plaintext plain_sum(to_string(sum));
    Ciphertext sum_encrypted_single;
    encryptor.encrypt(plain_sum,sum_encrypted_single);
    //SELECT SUM(Height) FROM example_table WHERE Age = 𝐻(23)
    //considerar usar add_many quando estiver na query
    for(int i=0;i<11;i++){
        evaluator.add_inplace(sum_encrypted_single,cypher[i][0]);
    }
    //decriptacao usando private
    Decryptor decryptor(context, db_seckey);
    decryptor.decrypt(sum_encrypted_single, buffer_decrypted);
    sscanf(buffer_decrypted.to_string().c_str(),"%x",&sum);
    cout << "Single is: " << sum << endl;
    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(sum_encrypted_single) << " bits";
}