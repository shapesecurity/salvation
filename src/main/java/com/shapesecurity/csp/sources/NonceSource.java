package com.shapesecurity.csp.sources;

import com.shapesecurity.csp.Base64Value;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class NonceSource implements SourceExpression, MatchesNonce {
    @Nonnull
    private final Base64Value value;

    public NonceSource(@Nonnull Base64Value value) {
        this.value = value;
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof NonceSource)) return false;
        return this.value.equals(((NonceSource) other).value);
    }

    @Override
    public int hashCode() {
        return this.value.hashCode();
    }

    public boolean matchesNonce(@Nonnull Base64Value nonce) {
        return this.value.equals(value);
    }

    @Nonnull
    @Override
    public String show() {
        return "'nonce-" + this.value.show() + "'";
    }
}
