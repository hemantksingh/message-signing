package com.inivaran.messagesigning;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

public class VerifyRequestCommand {
    private static final String DOUBLE_QUOTE = "\"";
    private static final String EMPTY_STRING = "";
    public final List<String> errors = new ArrayList<>();
    private final Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private final URI uri;
    private final String method;
    private final String contentType;
    private final String signatureMetadata;
    private final String signatureValue;
    private final String body;
    private final String signatureMethod;
    private final String signatureVersion;
    private final String clientId;
    private final String destination;
    private final String cl4nMethod;
    private final String requestId;

    public VerifyRequestCommand(VerifyRequestDetail detail) {
        headers.putAll(detail.headers);
        method = parseMethod(detail.method);
        uri = parseUrl(detail.url);
        body = parseInput(detail.body, "No request body found.");
        contentType = parseContentType("Content-Type");
        signatureMetadata = parseHeader("X-Bar-Signature-Metadata");
        signatureValue = parseHeader("X-Bar-Signature-Value");

        Map<String, String> signatureMetadataEntries = toMap(signatureMetadata);
        signatureMethod = parseInput(
                signatureMetadataEntries.get("signature-method"),
                "signature-method is not supported/missing.");
        signatureVersion = parseInput(
                signatureMetadataEntries.get("signature-version"),
                "signature-version is not supported/missing.");
        requestId = parseInput(
                signatureMetadataEntries.get("request-id"),
                "request-id invalid/missing.");
        clientId = parseInput(
                signatureMetadataEntries.get("client-id"),
                "client-id invalid/missing.");
        destination = parseInput(
                signatureMetadataEntries.get("destination"),
                "destination missing or invalid.");
        cl4nMethod = parseInput(
                signatureMetadataEntries.get("c14n-method"),
                "c14n-method missing or invalid.");

        String signedHeadersValue = parseInput(signatureMetadataEntries.get("signed-headers"), "signed-headers invalid/missing.");
        if (!isNullOrEmpty(signedHeadersValue)) {
            String[] signedHeaders = signatureMetadataEntries
                    .get("signed-headers")
                    .replace(DOUBLE_QUOTE, EMPTY_STRING)
                    .split(",");
            if (!Arrays.asList(signedHeaders).contains("X-BAR-SIGNATURE-METADATA"))
                errors.add("signed-headers does not include mandatory headers (X-Bar-Signature-Metadata).");
            if (!Arrays.asList(signedHeaders).contains("CONTENT-TYPE"))
                errors.add("signed-headers does not include mandatory headers (Content-Type).");
            parseInput(headers.get("CONTENT-TYPE"), "signed-headers contains headers missing from the request.");
        }

        if (isNullOrEmpty(signatureMetadataEntries.get("request-timestamp"))) {
            errors.add("timestamp invalid / missing (timestamp not UNIX epoch formatted or missing.");
        } else {
            String s = signatureMetadataEntries.get("request-timestamp");
            try {
                new java.util.Date(Long.valueOf(s.replace(DOUBLE_QUOTE, EMPTY_STRING)));
            } catch (Exception e) {
                errors.add("timestamp invalid / missing (timestamp not UNIX epoch formatted or missing.");
            }
        }
    }

    private boolean isNullOrEmpty(String value) {
        return value == null || value.length() == 0;
    }

    private Map<String, String> toMap(String headerValue) {
        Map<String, String> signatureMetadataEntries = new HashMap<>();
        if (headerValue == null) return signatureMetadataEntries;

        for (String entry : headerValue.split(";")) {
            String[] values = entry.split("=");
            if (values.length > 1)
                signatureMetadataEntries.put(values[0], values[1]);
        }
        return signatureMetadataEntries;
    }

    private String parseInput(String input, String error) {
        if (isNullOrEmpty(input)) {
            errors.add(error);
        }
        return input;
    }

    private String parseHeader(String name) {
        String value = headers.get(name);
        parseInput(value, String.format("%s header invalid/missing.", name));
        return value;
    }


    private String parseContentType(String name) {
        String value = headers.get(name);
        if (isNullOrEmpty(value)) {
            errors.add("Content-Type header is missing.");
        } else if (!value.equals("application/x-www-form-urlencoded"))
            errors.add("Unrecognized Content-Type is not supported.");
        return value;
    }

    private String parseMethod(String method) {
        String[] allowedHttpMethods = {"GET", "POST", "HEAD", "PUT", "DELETE"};
        if (!Arrays.asList(allowedHttpMethods).contains(method)) {
            errors.add("Invalid HTTP method (must be GET, POST, HEAD, PUT or DELETE).");
            return null;
        }
        return method;
    }

    private URI parseUrl(String url) {
        URI result;
        try {
            result = new URI(url);
        } catch (URISyntaxException e) {
            result = null;
        }
        URI uri = result;
        if (uri == null) {
            errors.add("Unrecognized Url, contains invalid characters.");
        }

        if (uri != null && uri.getFragment() != null) {
            errors.add("URL fragment is not supported.");
        }

        if (uri != null && !uri.isAbsolute()) {
            errors.add("URI contains relative paths (not permitted).");
        }
        return uri;
    }

    public boolean isValid() {
        return errors.isEmpty();
    }
}
