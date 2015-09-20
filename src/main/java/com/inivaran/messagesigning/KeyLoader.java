package com.inivaran.messagesigning;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.util.function.Function;

public class KeyLoader {

    private final String algorithm;
    private final Function<byte[], KeySpec> privateKeySpecSupplier;
    private final Function<byte[], KeySpec> publicKeySpecSupplier;

    public KeyLoader(String algorithm,
                     Function<byte[], KeySpec> privateKeySpecSupplier,
                     Function<byte[], KeySpec> publicKeySpecSupplier) {
        this.algorithm = algorithm;
        this.privateKeySpecSupplier = privateKeySpecSupplier;
        this.publicKeySpecSupplier = publicKeySpecSupplier;
    }

    public PrivateKey loadPrivateKey(String filename) throws KeyLoaderException {
        try {
            File file = new File(filename);
            try (FileInputStream fis = new FileInputStream(file)) {
                try (DataInputStream dis = new DataInputStream(fis)) {
                    byte[] keyBytes;
                    keyBytes = new byte[(int) file.length()];
                    dis.readFully(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                    return keyFactory.generatePrivate(privateKeySpecSupplier.apply(keyBytes));
                }
            }

        } catch (Exception e) {
            String msg = String.format("Failed to load private key for file '%s'", filename);
            throw new KeyLoaderException(msg, e);
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
                    KeyFactory kf = KeyFactory.getInstance(algorithm);

                    return kf.generatePublic(publicKeySpecSupplier.apply(keyBytes));
                }
            }

        } catch (Exception e) {
            String msg = String.format("Failed to load public key for file '%s'", filename);
            throw new KeyLoaderException(msg, e);
        }
    }
}
