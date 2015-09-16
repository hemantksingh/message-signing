package com.inivaran.messagesigning;

import java.util.Collections;
import java.util.List;

public class VerificationResult {
    public final boolean verified;
    public final List<String> errors;

    private VerificationResult(boolean verified, List<String> errors) {
        this.verified = verified;
        this.errors = errors;
    }

    public static VerificationResult failure(List<String> errors) {
        return new VerificationResult(false,
                Collections.unmodifiableList(errors == null
                        ? Collections.emptyList() : errors));
    }

    public static VerificationResult success(boolean verified) {
        return new VerificationResult(verified,
                Collections.unmodifiableList(Collections.emptyList()));
    }
}
