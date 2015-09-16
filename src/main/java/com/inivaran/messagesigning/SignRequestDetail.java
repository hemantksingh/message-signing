package com.inivaran.messagesigning;

import java.util.Map;

public class SignRequestDetail {
    public String clientId;
    public String path;
    public Integer requestId;
    public Long requestTimestamp;
    public String method;
    public String body;
    public Map<String, String> headers;
}
