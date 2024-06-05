mod authentication;
mod storage;
mod cryptography;

use storage::file::File;
use storage::folder::Folder;
use storage::server::Server;
use authentication::user::User;
use cryptography::cryptography::{get_random_key, hash_password, symmetric_encrypt, symmetric_decrypt};

use argon2::password_hash::SaltString;

fn main() {
    print_title();
    println!("-------------------------------------------------------------");
    println!("Welcome to SafeStore, a secure file storage system");
    println!("-------------------------------------------------------------");
    println!();
    let mut server = storage::server::Server::new();
    println!("[DEBUG] Creating Alice and Bob's accounts...");
    create_and_add_alice(&mut server);
    let alice_id = server.get_user(&"Alice".as_bytes().to_vec()).unwrap().id.clone();
    create_and_add_bob(&mut server);
    
    println!("[DEBUG] Alice and Bob's accounts have been created");
    server.display_users();
    println!("[DEBUG] Alice and Bob's root folders have been created");
    server.display_root_folders();

    println!("-------------------------------------------------------------");
    println!("                      LOGIN PROCEDURE                        ");
    println!("-------------------------------------------------------------");
    println!("[DEBUG] Alice wants to log in...");
    // Alice types in her password
    let typedpassword: Vec<u8> = "password".as_bytes().to_vec();
    let (typed_hash, _) = hash_password(
        typedpassword.clone(), 
        server.get_password_salt(
            "Alice".as_bytes().to_vec()).as_ref()
        );
    let (typed_challenge_hash, _) = hash_password(typed_hash.clone(), Some(&SaltString::encode_b64(alice_id.as_bytes()).unwrap()));
    
    // Alice requests to login
    let (root_folder, enc_master_key) = 
        server
            .login(
                &"Alice".as_bytes().to_vec(), 
                typed_challenge_hash.clone()
        );
    
    // Alice can decrypt her master key
    let dec_master_key = symmetric_decrypt(&typed_hash, enc_master_key.clone());
    let mut dec_folder = root_folder.symmetric_decrypt(dec_master_key.to_vec(), true);
    dec_folder.add_file(File::factory(&"Alice".as_bytes().to_vec()), get_random_key().unwrap().to_vec());
    println!("{}", dec_folder.display(0));
    
    println!("-------------------------------------------------------------");
    println!("                 CHANGE PASSWORD PROCEDURE                   ");
    println!("-------------------------------------------------------------");
    println!("[DEBUG] Alice wants to change her password...");
    // Alice decides to change her password
    let new_password = "newpassword".as_bytes().to_vec();
    let (new_password_hash, new_password_salt) = hash_password(new_password.clone(), None);
    let (new_challenge_hash, _) = hash_password(new_password_hash.clone(), Some(&SaltString::encode_b64(alice_id.as_bytes()).unwrap()));
    let (new_master_key, _) = hash_password(new_password_hash.clone(), None);
    let new_enc_master_key = symmetric_encrypt(&new_password_hash, new_master_key.to_vec());
    let new_enc_folder = dec_folder.symmetric_encrypt(new_master_key.to_vec(), true);
    
    println!("[DEBUG] Alice's password has been changed");
    println!("[DEBUG] Alice logs out and provides the new hashes associated with her new password");
    // Alice logs out and provides the new hashes associated with her new password 
    server.logout("Alice".as_bytes().to_vec(), new_enc_folder, new_enc_master_key, typed_hash.clone(), Some(new_challenge_hash.clone()), Some(new_password_salt.clone()));
    
    println!("[DEBUG] Alice logs in again using her new password");
    // Alice wants to log in again using her newly set password
    let new_password_typed = "newpassword".as_bytes().to_vec();
    let (new_hash_typed, _) = hash_password(new_password_typed.clone(), server.get_password_salt("Alice".as_bytes().to_vec()).as_ref());
    let (new_challenge_hash_typed, _) = hash_password(new_hash_typed.clone(), Some(&SaltString::encode_b64(alice_id.as_bytes()).unwrap()));
    
    let (root_folder, enc_master_key) = server.login(&"Alice".as_bytes().to_vec(), new_challenge_hash_typed.clone());
    let dec_master_key = symmetric_decrypt(&new_hash_typed, enc_master_key.clone());
    let dec_folder = root_folder.symmetric_decrypt(dec_master_key.to_vec(), true);
    
    // Alice consults her root folder
    println!("{}", dec_folder.display(0));

    println!("-------------------------------------------------------------");
    println!("                  SHARING FOLDER PROCEDURE                   ");
    println!("-------------------------------------------------------------");
    println!("[DEBUG] Alice wants to share the home folder with Bob...");
    println!("[DEBUG] Alice encrypts the home folder with Bob's public key");
    
    let home_folder = dec_folder.folders.iter().find(|folder| folder.name == "home".as_bytes().to_vec()).unwrap();
    let bob_keypair = server.get_user(&"Bob".as_bytes().to_vec()).unwrap().keypair;
    let alice_keypair = server.get_user(&"Alice".as_bytes().to_vec()).unwrap().keypair;

    let enc_home_folder = home_folder.asymmetric_encrypt(bob_keypair, alice_keypair);
    
    println!("[DEBUG] Bob can now attempt to decrypt the home folder using his private key");
    let dec_home_folder = enc_home_folder.asymmetric_decrypt(bob_keypair, alice_keypair);
    
    println!("{}", dec_home_folder.display(1));
}

pub fn create_and_add_alice(server: &mut Server) {
    let alice = User::factory(Some("Alice".as_bytes().to_vec()));

    let alice_password = "password".as_bytes().to_vec();
    let alice_id = alice.id.clone();
    
    let (password_hash, password_salt) = hash_password(alice_password, None);
    
    let challenge_salt = SaltString::encode_b64(alice_id.as_bytes()).unwrap();
    let (challenge_hash, challenge_salt) = hash_password(password_hash.clone(), Some(&challenge_salt));
    
    let (master_key, _) = hash_password(password_hash.clone(), None);
    let enc_master_key = symmetric_encrypt(&password_hash, master_key.to_vec());

    let mut alice_root_folder = Folder::new(alice_id.as_bytes().to_vec(), alice.name.clone());
    
    let mut other_folder = Folder::new("home".as_bytes().to_vec(), alice.name.clone());
    other_folder.add_file(File::factory(&alice.name), get_random_key().unwrap().to_vec());
    
    alice_root_folder.add_folder(other_folder, get_random_key().unwrap().to_vec());
    alice_root_folder.add_file(File::factory(&alice.name), get_random_key().unwrap().to_vec());
    let enc_alice_root_folder = alice_root_folder.symmetric_encrypt(master_key.to_vec(), true);

    server.add_user(alice, enc_master_key, password_salt, challenge_salt.clone(), challenge_hash.clone(), enc_alice_root_folder.clone());
}

pub fn create_and_add_bob(server: &mut Server) {
    let bob = User::factory(Some("Bob".as_bytes().to_vec()));

    let bob_password = "password".as_bytes().to_vec();
    let bob_id = bob.id.clone();
    
    let (password_hash, password_salt) = hash_password(bob_password, None);
    
    let challenge_salt = SaltString::encode_b64(bob_id.as_bytes()).unwrap();
    let (challenge_hash, challenge_salt) = hash_password(password_hash.clone(), Some(&challenge_salt));
    
    let (master_key, _) = hash_password(password_hash.clone(), None);
    let enc_master_key = symmetric_encrypt(&password_hash, master_key.to_vec());

    let mut bob_root_folder = Folder::new(bob_id.as_bytes().to_vec(), bob.name.clone());

    bob_root_folder.add_file(File::factory(&bob.name), get_random_key().unwrap().to_vec());
    let enc_bob_root_folder = bob_root_folder.symmetric_encrypt(master_key.to_vec(), true);

    server.add_user(bob, enc_master_key, password_salt, challenge_salt.clone(), challenge_hash.clone(), enc_bob_root_folder.clone());
}

pub fn print_title() {
    let title_string = r" .----------------.  .----------------.  .----------------.  .----------------. ";
    let title_string1 = r"| .--------------. || .--------------. || .--------------. || .--------------. |";
    let title_string2 = r"| |    _______   | || |  _________   | || |    _______   | || |  _________   | |";
    let title_string3 = r"| |   /  ___  |  | || | |_   ___  |  | || |   /  ___  |  | || | |  _   _  |  | |";
    let title_string4 = r"| |  |  (__ \_|  | || |   | |_  \_|  | || |  |  (__ \_|  | || | |_/ | | \_|  | |";
    let title_string5 = r"| |   '.___`-.   | || |   |  _|      | || |   '.___`-.   | || |     | |      | |";
    let title_string6 = r"| |  |`\____) |  | || |  _| |_       | || |  |`\____) |  | || |    _| |_     | |";
    let title_string7 = r"| |  |_______.'  | || | |_____|      | || |  |_______.'  | || |   |_____|    | |";
    let title_string8 = r"| |              | || |              | || |              | || |              | |";
    let title_string9 = r"| '--------------' || '--------------' || '--------------' || '--------------' |";
    let title_string10 = r" '----------------'  '----------------'  '----------------'  '----------------' ";

    println!("{}", title_string);
    println!("{}", title_string1);
    println!("{}", title_string2);
    println!("{}", title_string3);
    println!("{}", title_string4);
    println!("{}", title_string5);
    println!("{}", title_string6);
    println!("{}", title_string7);
    println!("{}", title_string8);
    println!("{}", title_string9);
    println!("{}", title_string10);
    println!("By Titus Abele, 2024");
}