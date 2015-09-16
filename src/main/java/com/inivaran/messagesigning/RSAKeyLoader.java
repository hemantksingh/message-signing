package com.inivaran.messagesigning;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAKeyLoader {

    public PrivateKey loadPrivateKey(String filename) throws KeyLoaderException {
        try {
            File file = new File(filename);
            try (FileInputStream fis = new FileInputStream(file)) {
                try (DataInputStream dis = new DataInputStream(fis)) {
                    byte[] keyBytes;
                    keyBytes = new byte[(int) file.length()];
                    dis.readFully(keyBytes);
                    PKCS8EncodedKeySpec spec =
                            new PKCS8EncodedKeySpec(keyBytes);
                    KeyFactory kf = KeyFactory.getInstance("RSA");

                    return kf.generatePrivate(spec);
                }
            }

        } catch (Exception e) {
            throw new KeyLoaderException("Failed to load private key", e);
        }
    }

    public PublicKey loadPublicKey(String filename) throws KeyLoaderException {
        try {
            File file = new File(filename);
            try (FileInputStream fis = new FileInputStream(file)) {
                try (DataInputStream dis = new DataInputStream(fis)) {
                    byte[] keyBytes;
                    keyBytes = new byte[(int) file.length()];
                    dis.readFully(keyBytes);
                    X509EncodedKeySpec spec =
                            new X509EncodedKeySpec(keyBytes);
                    KeyFactory kf = KeyFactory.getInstance("RSA");

                    return kf.generatePublic(spec);
                }
            }

        } catch (Exception e) {
            throw new KeyLoaderException("Failed to load public key", e);
        }
    }
}
