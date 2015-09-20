package com.inivaran.messagesigning;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

public class RESTMessageSigning {

    public XBarSignature signRequest(PrivateKey privateKey, SignRequestDetail detail)
            throws MessageSigningException {

        List<String> signedHeaders = new ArrayList<>();
        signedHeaders.add("X-BAR-SIGNATURE-METADATA");
        signedHeaders.add("CONTENT-TYPE");

        XBarSignature signature = new XBarSignature("RSAwithSHA256/PSS",
                "1",
                "None",
                signedHeaders,
                detail.clientId,
                detail.requestPath,
                detail.requestId,
                detail.requestTimestamp,
                ""
        );

        Map<String, String> headers = new HashMap<>(detail.requestHeaders);
        headers.put("X-BAR-SIGNATURE-METADATA", signature.Metadata);

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

        return signature.assignValue(signatureValue);
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
}
