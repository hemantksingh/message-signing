package com.inivaran.messagesigning;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import static com.inivaran.messagesigning.CanonicalMessage.buildCanonicalRequest;
import static com.inivaran.messagesigning.CanonicalMessage.buildSignatureMetadata;

public class RESTMessageSigning {

    public XBarSignature signRequest(PrivateKey privateKey, SignRequestDetail detail)
            throws MessageSigningException {

        String signatureMetadata = buildSignatureMetadata(detail.clientId,
                detail.path,
                detail.requestId,
                detail.requestTimestamp);

        Map<String, String> headers = addMetadataHeader(detail, signatureMetadata);

        String canonicalRequest = buildCanonicalRequest(detail.method,
                detail.path,
                detail.body,
                headers);

        MessageSigning rsaMessageSigning = new MessageSigning();
        String signatureValue;
        try {
            byte[] sign = rsaMessageSigning.sign(canonicalRequest, privateKey);
            signatureValue = new BASE64Encoder().encode(sign);
        } catch (Exception e) {
            throw new MessageSigningException("Problem signing request", e);
        }

        return new XBarSignature(signatureValue, signatureMetadata);
    }

    private Map<String, String> addMetadataHeader(SignRequestDetail signRequestDetails, String metadata) {
        Map<String, String> headerBuilder = new HashMap<>();
        for (Map.Entry<String, String> entry : signRequestDetails.headers.entrySet()) {
            headerBuilder.put(entry.getKey(), entry.getValue());
        }
        headerBuilder.put("X-BAR-SIGNATURE-METADATA", metadata);

        return headerBuilder;
    }

    public VerificationResult verifyRequest(PublicKey publicKey, VerifyRequestDetail detail)
            throws MessageSigningException {

        VerifyRequestCommand command =  new VerifyRequestCommand(detail);
        if(!command.isValid())
            return VerificationResult.failure(command.errors);

        String canonicalRequest = buildCanonicalRequest(detail.method,
                detail.url,
                detail.body,
                detail.headers);

        MessageSigning rsaMessageSigning = new MessageSigning();
        try {
        byte[] signature = new BASE64Decoder().decodeBuffer(getSignatureFromHeaders(detail.headers));
            boolean verify = rsaMessageSigning.verify(canonicalRequest, signature, publicKey);
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
                        entry.getValue().toUpperCase()));
        return newMap;
    }
}
