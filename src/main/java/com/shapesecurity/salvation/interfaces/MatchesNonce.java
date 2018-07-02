package com.shapesecurity.salvation.interfaces;

import javax.annotation.Nonnull;

public interface MatchesNonce {
	boolean matchesNonce(@Nonnull String nonce);
}
