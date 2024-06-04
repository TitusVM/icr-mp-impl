mod authentication;
mod storage;
mod cryptography;

use storage::file::File;
use storage::folder::Folder;
use authentication::user::User;
use cryptography::cryptography::{get_random_key, hash_password, encrypt, decrypt};

use argon2::password_hash::SaltString;
use dryoc::sign::*;
use dryoc::dryocbox::*;
use uuid::Uuid;

fn main() {
    let mut server = storage::server::Server::new();


    let user1 = User::factory();
    println!("Our first user: {}", user1.display_info());

    let user1password = "password".as_bytes().to_vec();
    let user_id = user1.id.clone();
    let salt_string = SaltString::encode_b64(user_id.as_bytes()).unwrap();

    let (password_hash, _) = hash_password(user1password, Some(&salt_string));
    
    let (challenge_hash, challenge_salt) = hash_password(password_hash.clone(), None);
    
    let (master_key, _) = hash_password(password_hash.clone(), None);
    let enc_master_key = encrypt(&password_hash, master_key.to_vec());

    let username = user1.name.clone();

    let mut user1_root_folder = Folder::new(user_id.as_bytes().to_vec(), user1.name.clone());
    println!("We named the folder: {:?}", Uuid::from_bytes(*user_id.as_bytes().to_vec().as_array()));
    user1_root_folder.add_file(File::factory(), get_random_key().unwrap().to_vec());
    let user1_root_folder = user1_root_folder.encrypt(master_key.to_vec(), true);

    server.add_user(user1, enc_master_key, challenge_salt.clone(), challenge_hash.clone(), user1_root_folder.clone());


    let typedpassword = "password".as_bytes().to_vec();
    let typed_salt = SaltString::encode_b64(user_id.as_bytes()).unwrap();
    let (typed_hash, _) = hash_password(typedpassword.clone(), Some(&typed_salt));


    let (root_folder, enc_master_key) = server.login(username, typed_hash.clone());
    
    let dec_master_key = decrypt(&typed_hash, enc_master_key.clone());
    let dec_folder = root_folder.decrypt(dec_master_key.to_vec(), true);
    println!("{}", dec_folder.display(0));



    // let keypair = SigningKeyPair::gen_with_defaults();
    // let message = b"Fair is foul, and foul is fair: Hover through the fog and filthy air.";

    // // Sign the message, using default types (stack-allocated byte array, Vec<u8>)
    // let signed_message = keypair.sign_with_defaults(message).expect("signing failed");

    // // Verify the message signature
    // signed_message
    //     .verify(&keypair.public_key)
    //     .expect("verification failed");

    // let sender_keypair = KeyPair::gen();
    // let recipient_keypair = KeyPair::gen();

    // // Randomly generate a nonce
    // let nonce = Nonce::gen();

    // let file = File::factory();
    // let mut folder = Folder::new(vec![1, 2, 3], "folder".as_bytes().to_vec(), vec![4, 5, 6]);
    // folder.add_file(file, get_random_key().unwrap().to_vec());

    // println!("{}", folder.display(0));

    // let message = folder.to_bytes();

    // // Encrypt the message into a Vec<u8>-based box.
    // let dryocbox = DryocBox::encrypt_to_vecbox(
    //     &message,
    //     &nonce,
    //     &recipient_keypair.public_key,
    //     &sender_keypair.secret_key,
    // )
    // .expect("unable to encrypt");

    // // Convert into a libsodium compatible box as a Vec<u8>
    // let sodium_box = dryocbox.to_vec();

    // // Load the libsodium box into a DryocBox
    // let dryocbox = DryocBox::from_bytes(&sodium_box).expect("failed to read box");

    // // Decrypt the same box back to the original message, with the sender/recipient
    // // keypairs flipped.
    // let decrypted = dryocbox
    //     .decrypt_to_vec(
    //         &nonce,
    //         &sender_keypair.public_key,
    //         &recipient_keypair.secret_key,
    //     )
    //     .expect("unable to decrypt");

    // let folder = Folder::from_bytes(decrypted);
    // println!("{}", folder.display(0));
    

    // let user = User::factory();
    // let file1 = File::factory();
    // let file2 = File::factory();
    // let file3 = File::factory();

    // println!("Our first user: {}", user.display_info());

    // let mut folder1 = Folder::new(vec![7, 8, 9], "folder1".as_bytes().to_vec(), user.id.as_bytes().to_vec());
    
    // let key1 = get_random_key().unwrap();
    // let key2 = get_random_key().unwrap();

    // folder1.add_file(file1, key1.to_vec())
    // folder1.add_file(file2, key2.to_vec());

    // let key3 = get_random_key().unwrap();

    // let mut folder2 = Folder::new(vec![10, 11, 12], "folder2".as_bytes().to_vec(), user.id.as_bytes().to_vec());
    
    // let key4 = get_random_key().unwrap();

    // folder2.add_file(file3, key3.to_vec());
    // folder2.add_folder(folder1, key4.to_vec());

    // // println!("{}", folder2.display(0));

    // let master_key = get_random_key().unwrap();

    // let encrypted_folder = folder2.encrypt(master_key.to_vec());

    // println!("{}", encrypted_folder.display(0));
    
    
    // // Setting a password
    // let set_password = String::from("password");
    // let (password_hash, salt) = hash_password(&set_password, None);

    // let enc_master_key = encrypt(&password_hash, master_key.to_vec());

    // let mut typed_password = String::new();
    // print!("Please enter your password: ");
    // let _=stdout().flush();
    // stdin().read_line(&mut typed_password).expect("Did not enter a correct string");
    // if let Some('\n')=typed_password.chars().next_back() {
    //     typed_password.pop();
    // }
    // if let Some('\r')=typed_password.chars().next_back() {
    //     typed_password.pop();
    // }

    // let (typed_password_hash, _) = hash_password(&typed_password, Some(&salt));
    // let dec_master_key = decrypt(&typed_password_hash, enc_master_key.clone());

    // let decrypted_folder = encrypted_folder.decrypt(dec_master_key.to_vec());

    // println!("{}", decrypted_folder.display(0));

   
}

