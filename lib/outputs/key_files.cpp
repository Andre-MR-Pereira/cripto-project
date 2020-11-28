#include "key_files.h"

void file_output(PublicKey db_pubkey,SecretKey db_seckey){
    ofstream pb;
    ofstream sc;
    pb.open("lib/assets/certificates/database/db_pbkey.key",ios::binary);
    sc.open("lib/assets/certificates/database/db_sckey.key",ios::binary);
    db_pubkey.save(pb);
    db_seckey.save(sc);
}