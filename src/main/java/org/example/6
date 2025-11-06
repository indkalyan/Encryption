package com.signature.service;

import com.signature.dto.*;
import com.signature.entity.KeyPairEntity;
import com.signature.entity.SignatureEntity;
import com.signature.repository.KeyPairRepository;
import com.signature.repository.SignatureRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

@Service
@RequiredArgsConstructor
public class SignatureService {

    private final CryptoService cryptoService;
    private final KeyPairRepository keyPairRepository;
    private final SignatureRepository signatureRepository;

    /**
     * Generate RSA key pair and store in database
     */
    @Transactional
    public GenerateKeyResponse generateKeyPair(GenerateKeyRequest request) {
        try {
            // Generate RSA key pair
            KeyPair keyPair = cryptoService.generateRSAKeyPair(request.getKeySize());

            // Convert public key to PEM
            String publicKeyPem = cryptoService.publicKeyToPEM(keyPair.getPublic());

            // Encrypt private key with AES
            String encryptedPrivateKey = cryptoService.encryptPrivateKey(keyPair.getPrivate());

            // Save to database
            KeyPairEntity entity = new KeyPairEntity();
            entity.setPublicKeyPem(publicKeyPem);
            entity.setEncryptedPrivateKey(encryptedPrivateKey);
            entity.setKeySize(request.getKeySize());
            
            KeyPairEntity saved = keyPairRepository.save(entity);

            return new GenerateKeyResponse(
                saved.getId(),
                publicKeyPem,
                encryptedPrivateKey
            );

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate key pair: " + e.getMessage(), e);
        }
    }

    /**
     * Fetch public key by ID
     */
    public PublicKeyResponse getPublicKey(Long keyId) {
        KeyPairEntity entity = keyPairRepository.findById(keyId)
            .orElseThrow(() -> new RuntimeException("Key pair not found with ID: " + keyId));

        return new PublicKeyResponse(
            entity.getId(),
            entity.getPublicKeyPem(),
            entity.getKeySize()
        );
    }

    /**
     * Create digital signature
     */
    @Transactional
    public CreateSignatureResponse createSignature(CreateSignatureRequest request) {
        try {
            // Verify key pair exists
            KeyPairEntity keyPairEntity = keyPairRepository.findById(request.getKeyId())
                .orElseThrow(() -> new RuntimeException("Key pair not found with ID: " + request.getKeyId()));

            // Decrypt private key
            PrivateKey privateKey = cryptoService.decryptPrivateKey(request.getEncryptedPrivateKeyBase64());

            // Sign the data
            String signatureBase64 = cryptoService.signData(request.getData(), privateKey);

            // Hash the data for storage
            String dataHash = cryptoService.hashData(request.getData());

            // Save signature to database
            SignatureEntity signatureEntity = new SignatureEntity();
            signatureEntity.setKeyPairId(request.getKeyId());
            signatureEntity.setSignatureBase64(signatureBase64);
            signatureEntity.setPublicKeyPem(keyPairEntity.getPublicKeyPem());
            signatureEntity.setDataHash(dataHash);

            SignatureEntity saved = signatureRepository.save(signatureEntity);

            return new CreateSignatureResponse(
                saved.getId(),
                signatureBase64
            );

        } catch (Exception e) {
            throw new RuntimeException("Failed to create signature: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieve signature details
     */
    public SignatureDetailsResponse getSignature(Long signatureId) {
        SignatureEntity entity = signatureRepository.findById(signatureId)
            .orElseThrow(() -> new RuntimeException("Signature not found with ID: " + signatureId));

        return new SignatureDetailsResponse(
            entity.getId(),
            entity.getSignatureBase64(),
            entity.getPublicKeyPem()
        );
    }

    /**
     * Verify signature validity
     */
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) {
        try {
            // Fetch signature from database
            SignatureEntity entity = signatureRepository.findById(request.getSignatureId())
                .orElseThrow(() -> new RuntimeException("Signature not found with ID: " + request.getSignatureId()));

            // Parse public key from PEM
            PublicKey publicKey = cryptoService.pemToPublicKey(entity.getPublicKeyPem());

            // Verify signature
            boolean isValid = cryptoService.verifySignature(
                request.getData(),
                entity.getSignatureBase64(),
                publicKey
            );

            String message = isValid 
                ? "Signature is valid" 
                : "Signature is invalid";

            return new VerifySignatureResponse(isValid, message);

        } catch (Exception e) {
            return new VerifySignatureResponse(false, "Verification failed: " + e.getMessage());
        }
    }
}