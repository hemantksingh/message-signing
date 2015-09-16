package com.inivaran.messagesigning;

import org.junit.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;


public class VerifySignedMessage {

    @Test
    public void messageSignedWithValidSignatureIsVerified() throws KeyLoaderException, MessageSigningException {
        XBarSignature signature = signMessage();
        System.out.print(signature.metadata);

        String requestMethod = "POST";
        String requestPath = "https://sandbox.inivaran.com";
        String requestBody = "a=ab&b=cd";
        Map<String, String> requestHeaders = Collections.unmodifiableMap(new HashMap<String, String>() {
            {
                put("CONTENT-TYPE", "application/x-www-form-urlencoded");
                put("X-Bar-Signature-Metadata", signature.metadata);
                put("X-Bar-Signature-Value", signature.value);
            }
        });

        PublicKey publicKey = new RSAKeyLoader().loadPublicKey("src/test/resources/public_key.der");

        VerificationResult verificationResult = new RESTMessageSigning().verifyRequest(
                publicKey,
                new VerifyRequestDetail(requestMethod, requestPath, requestBody, requestHeaders));

        assertTrue(verificationResult.verified);
    }

    private XBarSignature signMessage() throws KeyLoaderException, MessageSigningException {
        String clientId = "external-client";
        Long requestTimestamp = 144077601900L;
        Integer requestId = 5;
        String requestMethod = "POST";
        String requestPath = "https://sandbox.inivaran.com";
        String requestBody = "a=ab&b=cd";
        Map<String, String> requestHeaders = Collections.unmodifiableMap(new HashMap<String, String>() {
            {
                put("CONTENT-TYPE", "application/x-www-form-urlencoded");
            }
        });

        SignRequestDetail detail = new SignRequestDetail(requestPath,
                requestMethod,
                requestBody,
                requestHeaders,
                clientId,
                requestTimestamp,
                requestId);

        PrivateKey privateKey = new RSAKeyLoader().loadPrivateKey("src/test/resources/private_key.der");

        return new RESTMessageSigning().signRequest(privateKey, detail);
    }
}
