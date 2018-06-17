package com.shapesecurity.salvation.interfaces;

import com.shapesecurity.salvation.data.Base64Value;
import com.shapesecurity.salvation.directiveValues.HashSource.HashAlgorithm;

import javax.annotation.Nonnull;

public interface MatchesHash {
	boolean matchesHash(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value hashValue);
}
