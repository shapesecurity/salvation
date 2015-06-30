package com.shapesecurity.csp.interfaces;

import com.shapesecurity.csp.data.Base64Value;
import com.shapesecurity.csp.directiveValues.HashSource.HashAlgorithm;

import javax.annotation.Nonnull;

public interface MatchesHash {
    boolean matchesHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue);
}
