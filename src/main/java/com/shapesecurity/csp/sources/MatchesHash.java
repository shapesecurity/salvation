package com.shapesecurity.csp.sources;

import com.shapesecurity.csp.Base64Value;
import com.shapesecurity.csp.sources.HashSource.HashAlgorithm;

import javax.annotation.Nonnull;

public interface MatchesHash {
    boolean matchesHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue);
}
