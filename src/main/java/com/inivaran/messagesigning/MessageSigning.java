package com.inivaran.messagesigning;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

public class MessageSigning {

    private final String ALGORITHM_NAME = "SHA256WITHRSA/PSS";
    private final String ENCODING = "UTF8";

    public byte[] sign(CanonicalMessage message, PrivateKey privateKey) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        byte[] data = message.toString().getBytes(ENCODING);
        Signature signature = Signature.getInstance(ALGORITHM_NAME);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public boolean verify(CanonicalMessage message, byte[] signature, PublicKey publicKey) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Signature rsaSignature = Signature.getInstance(ALGORITHM_NAME);
        rsaSignature.initVerify(publicKey);
        byte[] data = message.toString().getBytes(ENCODING);
        rsaSignature.update(data);
        return rsaSignature.verify(signature);
    }
}
