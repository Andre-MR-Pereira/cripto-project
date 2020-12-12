#include "database_encryption.h"

void db_key(SecretKey db_seckey,PublicKey db_pubkey){
    ofstream file;
    ofstream pb;
    ofstream sc;
    ofstream rel;

    //instanciacao da encriptacao
    EncryptionParameters parms(scheme_type::bfv);   //encriptacao em bfv para calculos em integers encriptados

    //parametros
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(1024);

    //contexto e validacao
    SEALContext context(parms);

    KeyGenerator keygen(context);   //instaciacao das chaves
    db_seckey = keygen.secret_key(); //criacao da secret_key
    //criacao public_key
    keygen.create_public_key(db_pubkey);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    file.open("lib/assets/certificates/database/parms.pem",ios::binary);
    parms.save(file);
    file.close();
    pb.open("lib/assets/certificates/database/db_pbkey.key",ios::binary);
    db_pubkey.save(pb);
    pb.close();
    sc.open("lib/assets/certificates/database/db_sckey.key",ios::binary);
    db_seckey.save(sc);
    sc.close();
    rel.open("lib/assets/certificates/database/db_relkey.key",ios::binary);
    relin_keys.save(rel);
    rel.close();
}

void key_confirm(SecretKey db_seckey,PublicKey db_pubkey){
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

    //decriptacao usando private
    Decryptor decryptor(context, db_seckey);

    //passar 6 para plaintext
    //print_line(__LINE__);
    int x = 69;
    Plaintext x_plain(to_string(x));
    cout << "Express x = " + to_string(x) + " as a plaintext polynomial 0x" + x_plain.to_string() + "." << endl;

    //encriptar o plaintext
    //print_line(__LINE__);
    Ciphertext x_encrypted;
    cout << "Encrypt x_plain to x_encrypted." << endl;
    encryptor.encrypt(x_plain, x_encrypted);
    cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;
    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits"
         << endl;

    //decriptar o cypherext
    Plaintext x_decrypted;
    cout << "    + decryption of x_encrypted: ";
    decryptor.decrypt(x_encrypted, x_decrypted);
    cout << "0x" << x_decrypted.to_string() << " ...... Correct." << endl;

    Plaintext x_plain_bin;
    Ciphertext x_encrypted_bin;
    //
    Plaintext x_decrypted_bin;

    std::string input_bin = std::bitset<32>(x).to_string(); //to binary
    std::cout<<input_bin<<"<-Binario\n";

    for(int i=0;i<32;i++){
        x_plain_bin=input_bin[i];
        encryptor.encrypt(x_plain_bin, x_encrypted_bin);
        decryptor.decrypt(x_encrypted_bin, x_decrypted_bin);
        cout << i << ":" << x_decrypted_bin.to_string() << " <-Binario" << endl;
    }

}