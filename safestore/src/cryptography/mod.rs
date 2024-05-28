pub mod cryptography {
    use aes_gcm::{
        aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Error, Key, Nonce
    };

    use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString, Output
        },
        Argon2
    }; 

    pub fn get_random_key() -> Result<[u8; 32], Error> {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Ok(key)
    }
    
    pub fn encrypt(key: &[u8], plaintext: Vec<u8>) -> Vec<u8> {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let cipher = Aes256Gcm::new(key);
    
        let ciphered_data = cipher.encrypt(&nonce, plaintext.as_ref())
            .expect("failed to encrypt");
        
        let mut encrypted_data: Vec<u8> = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphered_data);
    
        encrypted_data
    }
    
    pub fn decrypt(key: &[u8], encrypted_data: Vec<u8>) -> Vec<u8> {
        let key = Key::<Aes256Gcm>::from_slice(key);
    
        let (nonce_arr, ciphered_data) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_arr);
    
        let cipher = Aes256Gcm::new(key);
    
        let plaintext = cipher.decrypt(nonce, ciphered_data)
            .expect("failed to decrypt data");

        plaintext.to_vec()
    
    }

    pub fn hash_password(password: &str, given_salt: Option<&SaltString>) -> (Vec<u8>, SaltString) {
        let mut salt = SaltString::generate(&mut OsRng);
        if !given_salt.is_none() {
            salt = given_salt.unwrap().clone();
        }
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        let parsed_hash = PasswordHash::new(&password_hash);
        let hash = parsed_hash.unwrap().hash.unwrap().as_bytes().to_vec();
        return (hash, salt.clone());
    }
}