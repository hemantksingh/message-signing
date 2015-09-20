package com.inivaran.messagesigning;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class RESTMessageSigning {

    public XBarSignature signRequest(PrivateKey privateKey, SignRequestDetail detail)
            throws MessageSigningException {

        Map<String, String> headers = new HashMap<>(detail.requestHeaders);
        headers.put("X-BAR-SIGNATURE-METADATA", signatureMetadata(detail));

        CanonicalMessage canonicalMessage = new CanonicalMessage(detail.requestMethod,
                detail.requestPath,
                detail.requestBody,
                headers);

        MessageSigning rsaMessageSigning = new MessageSigning();
        String signatureValue;
        try {
            byte[] sign = rsaMessageSigning.sign(canonicalMessage, privateKey);
            signatureValue = new BASE64Encoder().encode(sign);
        } catch (Exception e) {
            throw new MessageSigningException("Problem signing request", e);
        }

        return new XBarSignature(signatureValue, signatureMetadata(detail));
    }

    public VerificationResult verifyRequest(PublicKey publicKey, VerifyRequestDetail detail)
            throws MessageSigningException {

        VerifyRequestCommand command =  new VerifyRequestCommand(detail);
        if(!command.isValid())
            return VerificationResult.failure(command.errors);

        CanonicalMessage canonicalMessage = new CanonicalMessage(
                detail.method,
                detail.url,
                detail.body,
                detail.headers);

        MessageSigning rsaMessageSigning = new MessageSigning();
        try {
        byte[] signature = new BASE64Decoder().decodeBuffer(getSignatureFromHeaders(detail.headers));
            boolean verify = rsaMessageSigning.verify(canonicalMessage, signature, publicKey);
            return VerificationResult.success(verify);

        } catch (Exception e) {
            throw new MessageSigningException("Problem verifying signature on the request", e);
        }
    }

    private String getSignatureFromHeaders(Map<String, String> headers) {
        Map<String, String> upperCaseHeaders = uppercaseMap(headers);
        return upperCaseHeaders.get("X-BAR-SIGNATURE-VALUE");
    }

    private static Map<String, String> uppercaseMap(Map<String, String> headers) {
        Map<String, String> newMap = new HashMap<>();

        headers.entrySet().stream().forEach(entry ->
                newMap.put(entry.getKey().toUpperCase(),
                        entry.getValue()));
        return newMap;
    }

    private static String signatureMetadata(SignRequestDetail detail) {
        Map<String, String> signatureMetadata = new TreeMap<>();
        signatureMetadata.put("signature-method", "RSAwithSHA256/PSS");
        signatureMetadata.put("signature-version", "1");
        signatureMetadata.put("signed-headers", "X-BAR-SIGNATURE-METADATA,CONTENT-TYPE");
        signatureMetadata.put("c14n-method", "None");

        signatureMetadata.put("client-id", detail.clientId);
        signatureMetadata.put("destination", detail.requestPath);
        signatureMetadata.put("request-id", detail.requestId.toString());
        signatureMetadata.put("request-timestamp", detail.requestTimestamp.toString());

        return signatureMetadata.entrySet()
                .stream()
                .map(entry -> String.format("%s=\"%s\"", entry.getKey(), entry.getValue()))
                .collect(Collectors.joining(";"));
    }
}
