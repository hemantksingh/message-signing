package com.inivaran.messagesigning;

import java.util.List;

import static java.util.Collections.emptyList;
import static java.util.Collections.unmodifiableList;

public class VerificationResult {
    public final boolean verified;
    public final List<String> errors;

    private VerificationResult(boolean verified, List<String> errors) {
        this.verified = verified;
        this.errors = errors;
    }

    public static VerificationResult failure(List<String> errors) {
        return new VerificationResult(false, unmodifiableList(errors == null
                        ? emptyList() : errors));
    }

    public static VerificationResult success(boolean verified) {
        return new VerificationResult(verified, emptyList());
    }
}
