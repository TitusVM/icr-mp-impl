pub mod cryptography {
    use aes_gcm::{
        aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Error, Key, Nonce
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
    
}