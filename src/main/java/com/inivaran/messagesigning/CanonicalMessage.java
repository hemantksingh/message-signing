package com.inivaran.messagesigning;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;
import java.util.stream.Collectors;

public class CanonicalMessage {
    public static String buildCanonicalRequest(String method,
                                               String path,
                                               String body,
                                               Map<String, String> headers) {

        return String.join("\n",
                method.toUpperCase(),
                buildCanonicalPath(path),
                buildCanonicalHeaders(headers),
                buildCanonicalBody(body));
    }

    public static String buildSignatureMetadata(String clientId, String destination,
                                                Integer requestId, Long requestTimestamp) {

        Map<String, String> signatureMetadata = new TreeMap<>();
        signatureMetadata.put("signature-method", "RSAwithSHA256/PSS");
        signatureMetadata.put("signature-version", "1");
        signatureMetadata.put("signed-headers", "X-BAR-SIGNATURE-METADATA,CONTENT-TYPE");
        signatureMetadata.put("c14n-method", "None");

        signatureMetadata.put("client-id", clientId);
        signatureMetadata.put("destination", destination);
        signatureMetadata.put("request-id", requestId.toString());
        signatureMetadata.put("request-timestamp", requestTimestamp.toString());

        return signatureMetadata.entrySet()
                .stream()
                .map(entry -> String.format("%s=\"%s\"", entry.getKey(), entry.getValue()))
                .collect(Collectors.joining(";"));
    }

    private static String buildCanonicalPath(String path) {
        try {
            return URLEncoder.encode(path, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return path.toLowerCase();
        }
    }

    private static String buildCanonicalHeaders(Map<String, String> headers) {

        Map<String, String> upperCaseHeaders = headers
                .entrySet()
                .stream()
                .collect(Collectors.toMap(entry -> entry.getKey().toUpperCase(), Map.Entry::getValue));

        String[] signedHeaders = Arrays.asList(upperCaseHeaders.get("X-BAR-SIGNATURE-METADATA").split(";"))
                .stream()
                .filter(s -> s.startsWith("signed-headers"))
                .map(s -> s.substring(s.indexOf("\"") + 1, s.lastIndexOf("\"")))
                .findFirst().orElse("")
                .split(",");

        return Arrays.asList(signedHeaders)
                .stream()
                .map(s -> urlEncode(s) + "=" + urlEncode(upperCaseHeaders.get(s)))
                .sorted()
                .collect(Collectors.joining("\n"));
    }

    private static String urlEncode(String input) {
        try {
            return URLEncoder.encode(input, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return input;
        }
    }


    private static String buildCanonicalBody(String body) {
       return Arrays.asList(body.split("&"))
                .stream()
                .map(s -> {
                    String[] entries = s.split("=");
                    return entries.length > 1 ? entries[0].toUpperCase() + "=" + entries[1] : s;
                })
                .collect(Collectors.joining("\n"));
    }
}
