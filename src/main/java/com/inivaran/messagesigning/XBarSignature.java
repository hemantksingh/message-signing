package com.inivaran.messagesigning;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static java.util.stream.Collectors.joining;

public class XBarSignature {
    public final String Value;
    private final String method;
    private final String version;
    private final List<String> signedHeaders;
    private final String cl4nMethod;
    public final String Metadata;
    private final String clientId;
    private final String requestPath;
    private final Integer requestId;
    private final Long requestTimestamp;

    public XBarSignature(String method,
                         String version,
                         String cl4nMethod,
                         List<String> signedHeaders,
                         String clientId,
                         String requestPath,
                         Integer requestId,
                         Long requestTimestamp,
                         String value) {

        this.clientId = clientId;
        this.requestPath = requestPath;
        this.requestId = requestId;
        this.requestTimestamp = requestTimestamp;
        this.Value = value;
        this.method = method;
        this.version = version;
        this.signedHeaders = signedHeaders;
        this.cl4nMethod = cl4nMethod;
        this.Metadata = getMetadata();
    }

    private String getMetadata() {

        Map<String, String> signatureMetadata = new TreeMap<>();
        signatureMetadata.put("signature-method", method);
        signatureMetadata.put("signature-version", version);
        signatureMetadata.put("signed-headers", signedHeaders.stream().collect(joining(",")));
        signatureMetadata.put("c14n-method", cl4nMethod);

        signatureMetadata.put("client-id", clientId);
        signatureMetadata.put("destination", requestPath);
        signatureMetadata.put("request-id", requestId.toString());
        signatureMetadata.put("request-timestamp", requestTimestamp.toString());

        return signatureMetadata.entrySet()
                .stream()
                .map(entry -> String.format("%s=\"%s\"", entry.getKey(), entry.getValue()))
                .collect(joining(";"));
    }

    public XBarSignature assignValue(String signatureValue) {
        return new XBarSignature(
                method, version, cl4nMethod, signedHeaders, clientId,
                requestPath,
                requestId,
                requestTimestamp,
                signatureValue
        );
    }
}
