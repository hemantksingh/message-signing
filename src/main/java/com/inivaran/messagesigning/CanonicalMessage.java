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

        return buildCanonicalMethod(method) + "\n" +
                buildCanonicalPath(path) + "\n" +
                buildCanonicalHeaders(headers) + "\n" +
                buildCanonicalPayload(body);
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

        List<String> list = new ArrayList<>();

        for (Map.Entry<String, String> entry : signatureMetadata.entrySet()) {
            list.add(String.format("%s=\"%s\"", entry.getKey(), entry.getValue()));
        }
        return list.stream().collect(Collectors.joining(";"));
    }

    public static String buildCanonicalMethod(String method) {
        return method.toUpperCase();
    }

    public static String buildCanonicalPath(String path) {
        try {
            return URLEncoder.encode(path, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return path.toLowerCase();
        }
    }

    public static String buildCanonicalHeaders(Map<String, String> headers) {

        Map<String, String> upperCaseHeaders = uppercaseMap(headers);

        List<String> signedHeadersList = getListOfHeadersToBeSigned(upperCaseHeaders);

        List<String> canonicalHeaders = extractHeaders(upperCaseHeaders, signedHeadersList);

        return canonicalHeaders.stream().sorted().collect(Collectors.joining("\n"));
    }

    private static Map<String, String> uppercaseMap(Map<String, String> headers) {
        Map<String, String> newMap = new HashMap<>();

         headers.entrySet().stream().forEach(entry ->
                 newMap.put(entry.getKey().toUpperCase(),
                            entry.getValue().toUpperCase()));
        return newMap;
    }

    private static List<String> extractHeaders(Map<String, String> upperCaseHeaders, List<String> signedHeadersList) {
        List<String> canonicalHeaders = new ArrayList<>();
        for (String signedHeader : signedHeadersList) {
            try {
                canonicalHeaders.add(URLEncoder.encode(signedHeader, "UTF-8") + "=" +
                        URLEncoder.encode(upperCaseHeaders.get(signedHeader), "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                canonicalHeaders.add(signedHeader + "=" + upperCaseHeaders.get(signedHeader));
            }
        }
        return canonicalHeaders;
    }

    private static List<String> getListOfHeadersToBeSigned(Map<String, String> upperCaseHeaders) {
        String metadata = upperCaseHeaders.get("X-BAR-SIGNATURE-METADATA");
        String signedHeaders = "";

        List<String> metaDataItems = Arrays.asList(metadata.split(";"));
        for (String item : metaDataItems) {
            if (item.startsWith("signed-headers")) {
                signedHeaders = item.substring(item.indexOf("\"") + 1, item.lastIndexOf("\""));
                signedHeaders = signedHeaders.toUpperCase();
            }
        }
        return Arrays.asList(signedHeaders.replaceAll(" ", "").split(","));
    }


    public static String buildCanonicalPayload(String body) {

        List<String> payloadList = Arrays.asList(body.split("&"));

        String canonicalPayload;
        List<String> upperCasePayloadList = new ArrayList<>();
        for(String payloadItem : payloadList){

            canonicalPayload = payloadItem.split("=")[0].toUpperCase() + "=" +
                    (payloadItem.split("=").length > 1 ? payloadItem.split("=")[1] : "" + "");
            upperCasePayloadList.add(canonicalPayload);
        }

       return upperCasePayloadList.stream()
               .sorted()
               .collect(Collectors.joining("\n"));
    }
}

