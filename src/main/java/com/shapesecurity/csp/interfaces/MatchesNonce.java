package com.shapesecurity.csp.interfaces;

import com.shapesecurity.csp.data.Base64Value;

import javax.annotation.Nonnull;

public interface MatchesNonce {
    boolean matchesNonce(@Nonnull String nonce);
}
