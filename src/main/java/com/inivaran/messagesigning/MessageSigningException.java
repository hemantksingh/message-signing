package com.inivaran.messagesigning;

public class MessageSigningException extends Exception {
    public MessageSigningException(String message, Exception e) {
        super(message, e);
    }
}
