package com.inivaran.messagesigning;

public class XBarSignature {
    public final String value;
    public final String metadata;

    public XBarSignature(String value, String metadata) {
        this.value = value;
        this.metadata = metadata;
    }
}
