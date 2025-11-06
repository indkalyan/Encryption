package com.signature.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "key_pairs")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class KeyPairEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, length = 5000)
    private String publicKeyPem;
    
    @Column(nullable = false, length = 10000)
    private String encryptedPrivateKey;
    
    @Column(nullable = false)
    private Integer keySize;
    
    @Column(nullable = false)
    private LocalDateTime createdAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}