package com.inivaran.messagesigning;

import java.util.List;

public class VerificationResult {
    public static VerificationResult failure(List<String> errors) {
        return new VerificationResult();
    }

    public static VerificationResult success(boolean verified) {
        return new VerificationResult();
    }
}
