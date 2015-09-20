package com.inivaran.messagesigning;

import org.junit.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

import static java.util.Collections.unmodifiableMap;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class VerifySignedMessage {

    @Test
    public void messageSignedWithValidSignatureIsVerified()
            throws KeyLoaderException, MessageSigningException, URISyntaxException {
        XBarSignature signature = signMessage();

        String requestMethod = "POST";
        String requestPath = "https://sandbox.inivaran.com";
        String requestBody = "a=ab&b=cd";
        Map<String, String> requestHeaders = unmodifiableMap(new HashMap<String, String>() {
            {
                put("CONTENT-TYPE", "application/x-www-form-urlencoded");
                put("X-Bar-Signature-Metadata", signature.Metadata);
                put("X-Bar-Signature-Value", signature.Value);
            }
        });

        String filename = getResourcePath("public_key.der").toString();
        PublicKey publicKey = new RSAKeyLoader().loadPublicKey(filename);

        VerificationResult verificationResult = new RESTMessageSigning().verifyRequest(
                publicKey,
                new VerifyRequestDetail(requestMethod, requestPath, requestBody, requestHeaders));

        assertTrue(verificationResult.verified);
    }


    @Test
    public void canonicalMessageIsInExpectedFormat() throws URISyntaxException, IOException {
        List<String> signedHeaders = new ArrayList<>();
        signedHeaders.add("X-BAR-SIGNATURE-METADATA");
        signedHeaders.add("CONTENT-TYPE");

        Map<String, String> requestHeaders = unmodifiableMap(new HashMap<String, String>() {
            {
                put("CONTENT-TYPE", "application/x-www-form-urlencoded");

                XBarSignature signature = new XBarSignature(
                        "RSAwithSHA256/PSS", "1", "None", signedHeaders, "external-client",
                        "https://sandbox.inivaran.com",
                        5,
                        144077601900L,
                        "");
                put("X-BAR-SIGNATURE-METADATA", signature.Metadata);
            }
        });

        CanonicalMessage message = new CanonicalMessage(
                "POST",
                "https://sandbox.inivaran.com",
                "a=ab&b=cd",
                requestHeaders);

        String expected = new String(Files.readAllBytes(getResourcePath("ExpectedCanonicalForm.txt")));
        assertEquals(expected, message.toString());
    }

    private static Path getResourcePath(String resourceName) throws URISyntaxException {
        URL resource = ClassLoader.getSystemClassLoader().getResource(resourceName);

        if(resource != null)
            return Paths.get(resource.toURI());
        return Paths.get("");
    }

    private XBarSignature signMessage() throws KeyLoaderException, MessageSigningException, URISyntaxException {
        String clientId = "external-client";
        Long requestTimestamp = 144077601900L;
        Integer requestId = 5;
        String requestMethod = "POST";
        String requestPath = "https://sandbox.inivaran.com";
        String requestBody = "a=ab&b=cd";
        Map<String, String> requestHeaders = unmodifiableMap(new HashMap<String, String>() {
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

        String filename = getResourcePath("private_key.der").toString();
        PrivateKey privateKey = new RSAKeyLoader().loadPrivateKey(filename);

        return new RESTMessageSigning().signRequest(privateKey, detail);
    }
}