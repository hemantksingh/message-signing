package com.inivaran.messagesigning;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;
import java.util.stream.Collectors;

public class CanonicalMessage {
    private final String requestMethod;
    private final String requestPath;
    private final String requestBody;
    private final Map<String, String> requestHeaders;

    public CanonicalMessage(String requestMethod,
                            String requestPath,
                            String requestBody,
                            Map<String, String> requestHeaders) {

        this.requestMethod = requestMethod;
        this.requestPath = requestPath;
        this.requestBody = requestBody;
        this.requestHeaders = requestHeaders;
    }

    @Override
    public String toString() {

        return String.join("\n",
                requestMethod.toUpperCase(),
                buildCanonicalPath(requestPath),
                buildCanonicalHeaders(requestHeaders),
                buildCanonicalBody(requestBody));
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
