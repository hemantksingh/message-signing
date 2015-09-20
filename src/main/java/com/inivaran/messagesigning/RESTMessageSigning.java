package com.inivaran.messagesigning;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

public class RESTMessageSigning {

    private final MessageSigning messageSigning;

    public RESTMessageSigning(MessageSigning messageSigning) {
        this.messageSigning = messageSigning;
    }

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

        String signatureValue = uncheckCall(() ->
                messageSigning.sign(canonicalMessage, privateKey));

        return signature.assignValue(signatureValue);
    }

    public VerificationResult verifyRequest(PublicKey publicKey, VerifyRequestDetail detail)
            throws MessageSigningException {

        VerifyRequestCommand command = new VerifyRequestCommand(detail);
        if (!command.isValid())
            return VerificationResult.failure(command.errors);

        CanonicalMessage canonicalMessage = new CanonicalMessage(
                detail.method,
                detail.url,
                detail.body,
                detail.headers);

        String signatureValue = getSignatureValue(detail.headers);
        boolean verify = uncheckCall(() ->
                messageSigning.verify(canonicalMessage, signatureValue, publicKey));
        return VerificationResult.success(verify);
    }

    private static <T> T uncheckCall(Callable<T> callable) {
        try {
            return callable.call();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getSignatureValue(Map<String, String> headers) {
        Map<String, String> upperCaseHeaders = new HashMap<>();

        headers.entrySet().stream().forEach(entry ->
                upperCaseHeaders.put(entry.getKey().toUpperCase(),
                        entry.getValue()));

        return upperCaseHeaders.get("X-BAR-SIGNATURE-VALUE");
    }
}
