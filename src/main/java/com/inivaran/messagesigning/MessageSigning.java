package com.inivaran.messagesigning;

import java.security.*;
import java.util.function.Function;

public class MessageSigning {

    private final Function<byte[], String> encoder;
    private final Function<String, byte[]> decoder;
    private final Provider provider;
    private final String encoding;
    private final String algorithmName;

    public MessageSigning(Function<byte[], String> encoder,
                          Function<String, byte[]> decoder,
                          Provider provider,
                          String algorithmName, String encoding) {

        this.encoder = encoder;
        this.decoder = decoder;
        this.provider = provider;
        this.encoding = encoding;
        this.algorithmName = algorithmName;
    }

    public String sign(CanonicalMessage message,
                       PrivateKey privateKey) throws Exception {
        Security.addProvider(provider);
        byte[] data = message.toString().getBytes(encoding);
        Signature signature = Signature.getInstance(algorithmName);
        signature.initSign(privateKey);
        signature.update(data);
        return encoder.apply(signature.sign());
    }

    public boolean verify(CanonicalMessage message,
                          String signature,
                          PublicKey publicKey) throws Exception {
        Security.addProvider(provider);
        Signature rsaSignature = Signature.getInstance(algorithmName);
        rsaSignature.initVerify(publicKey);
        byte[] data = message.toString().getBytes(encoding);
        rsaSignature.update(data);
        return rsaSignature.verify(decoder.apply(signature));
    }
}
