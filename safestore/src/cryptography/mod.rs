pub mod cryptography {
    use aes_gcm::{
        aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Error, Key
    };
    
    use dryoc::classic::crypto_box::*;
    use dryoc::constants::CRYPTO_BOX_MACBYTES;

    use argon2::{
    password_hash::{
        PasswordHasher, SaltString
        },
        Argon2
    };

    pub fn get_random_key() -> Result<[u8; 32], Error> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Ok(key)
    }
    
    pub fn symmetric_encrypt(key: &[u8], plaintext: Vec<u8>) -> Vec<u8> {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let cipher = Aes256Gcm::new(key);
    
        let ciphered_data = cipher.encrypt(&nonce, plaintext.as_ref())
            .expect("failed to encrypt");
        
        let mut encrypted_data: Vec<u8> = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphered_data);
    
        encrypted_data
    }
    
    pub fn symmetric_decrypt(key: &[u8], encrypted_data: Vec<u8>) -> Vec<u8> {
        let key = Key::<Aes256Gcm>::from_slice(key);
    
        let (nonce_arr, ciphered_data) = encrypted_data.split_at(12);
        let nonce = aes_gcm::Nonce::from_slice(nonce_arr);
    
        let cipher = Aes256Gcm::new(key);
    
        let plaintext = cipher.decrypt(nonce, ciphered_data)
            .expect("failed to decrypt data");

        plaintext.to_vec()
    
    }

    pub fn asymmetric_encrypt(sender_sk: SecretKey, recipient_pk: PublicKey, message: Vec<u8>) -> Vec<u8> {
        // nonce is just default for now
        let nonce = Nonce::default();
        let mut ciphertext = vec![0u8; message.len() + CRYPTO_BOX_MACBYTES];
        crypto_box_easy(&mut ciphertext, &message, &nonce, &recipient_pk, &sender_sk)
            .expect("encrypt failed");
        ciphertext
    }

    pub fn asymmetric_decrypt(sender_pk: PublicKey, recipient_sk: SecretKey, ciphertext: Vec<u8>) -> Vec<u8> {
        // nonce is just default for now
        let nonce = Nonce::default();
        let mut message = vec![0u8; ciphertext.len() - CRYPTO_BOX_MACBYTES];
        crypto_box_open_easy(&mut message, &ciphertext, &nonce, &sender_pk, &recipient_sk)
            .expect("decrypt failed");
        message
    }

    pub fn hash_password(password: Vec<u8>, given_salt: Option<&SaltString>) -> (Vec<u8>, SaltString) {
        let mut salt = SaltString::generate(&mut OsRng);
        if !given_salt.is_none() {
            salt = given_salt.unwrap().clone();
        }
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(&password, &salt);
        let hash = password_hash.unwrap().hash.unwrap().as_bytes().to_vec();
        return (hash, salt.clone());
    }
}