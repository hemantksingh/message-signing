package com.inivaran.messagesigning;

public class XBarSignature {
    private final String signatureValue;
    private final String signatureMetadata;

    public XBarSignature(String signatureValue, String signatureMetadata) {
        this.signatureValue = signatureValue;
        this.signatureMetadata = signatureMetadata;
    }
}
