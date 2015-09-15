package com.shapesecurity.csp.interfaces;

import javax.annotation.Nonnull;

public interface MatchesNonce {
    boolean matchesNonce(@Nonnull String nonce);
}
