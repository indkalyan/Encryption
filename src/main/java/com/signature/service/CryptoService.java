package com.signature.service;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class CryptoService {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA512withRSA";
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    /**
     * Generate RSA key pair
     */
    public KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    /**
     * Convert public key to PEM format
     */
    public String publicKeyToPEM(PublicKey publicKey) throws Exception {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(publicKey);
            pemWriter.flush();
        }
        return stringWriter.toString();
    }

    /**
     * Encrypt private key using AES-256-GCM
     */
    public String encryptPrivateKey(PrivateKey privateKey) throws Exception {
        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Encrypt private key
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        
        byte[] privateKeyBytes = privateKey.getEncoded();
        byte[] encryptedKey = cipher.doFinal(privateKeyBytes);

        // Combine: AES_KEY(32) + IV(12) + ENCRYPTED_DATA
        byte[] combined = new byte[32 + GCM_IV_LENGTH + encryptedKey.length];
        System.arraycopy(aesKey.getEncoded(), 0, combined, 0, 32);
        System.arraycopy(iv, 0, combined, 32, GCM_IV_LENGTH);
        System.arraycopy(encryptedKey, 0, combined, 32 + GCM_IV_LENGTH, encryptedKey.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Decrypt private key from AES-encrypted Base64 string
     */
    public PrivateKey decryptPrivateKey(String encryptedPrivateKeyBase64) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedPrivateKeyBase64);

        // Extract components
        byte[] aesKeyBytes = new byte[32];
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encryptedKey = new byte[combined.length - 32 - GCM_IV_LENGTH];

        System.arraycopy(combined, 0, aesKeyBytes, 0, 32);
        System.arraycopy(combined, 32, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(combined, 32 + GCM_IV_LENGTH, encryptedKey, 0, encryptedKey.length);

        // Decrypt
        SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
        
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);

        // Reconstruct private key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decryptedKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Parse PEM formatted public key
     */
    public PublicKey pemToPublicKey(String pemKey) throws Exception {
        try (PemReader pemReader = new PemReader(new StringReader(pemKey))) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(content);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return keyFactory.generatePublic(keySpec);
        }
    }

    /**
     * Sign data using SHA-512 with RSA
     */
    public String signData(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data.getBytes("UTF-8"));
        byte[] signedBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signedBytes);
    }

    /**
     * Verify signature using SHA-512 with RSA
     */
    public boolean verifySignature(String data, String signatureBase64, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data.getBytes("UTF-8"));
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        return signature.verify(signatureBytes);
    }

    /**
     * Hash data using SHA-512
     */
    public String hashData(String data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] hash = digest.digest(data.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
}