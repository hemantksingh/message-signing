package com.inivaran.messagesigning;

import java.util.HashMap;
import java.util.Map;

public class VerifyRequestDetail {
    public String method;
    public String url;
    public String body;
    public Map<String, String> headers = new HashMap<>();

    public VerifyRequestDetail(String requestMethod, String requestPath, String requestBody, Map<String, String> requestHeaders) {
        this.method = requestMethod;
        this.url = requestPath;
        this.body = requestBody;
        this.headers.putAll(requestHeaders);
    }
}
