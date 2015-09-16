package com.inivaran.messagesigning;

import java.util.Map;

public class SignRequestDetail {
    public String clientId;
    public String requestPath;
    public Integer requestId;
    public Long requestTimestamp;
    public String requestMethod;
    public String requestBody;
    public Map<String, String> requestHeaders;

    public SignRequestDetail(String requestPath,
                             String requestMethod,
                             String requestBody,
                             Map<String, String> requestHeaders,
                             String clientId,
                             Long requestTimestamp,
                             Integer requestId) {
        this.clientId = clientId;
        this.requestPath = requestPath;
        this.requestMethod = requestMethod;
        this.requestBody = requestBody;
        this.requestHeaders = requestHeaders;
        this.requestTimestamp = requestTimestamp;
        this.requestId = requestId;
    }
}
