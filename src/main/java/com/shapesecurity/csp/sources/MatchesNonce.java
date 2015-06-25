package com.shapesecurity.csp.sources;

import com.shapesecurity.csp.Base64Value;

import javax.annotation.Nonnull;

public interface MatchesNonce {
    boolean matchesNonce(@Nonnull Base64Value nonce);
}
