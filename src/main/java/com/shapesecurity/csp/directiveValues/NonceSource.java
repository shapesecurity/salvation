package com.shapesecurity.csp.directiveValues;

import com.shapesecurity.csp.data.Base64Value;
import com.shapesecurity.csp.interfaces.MatchesNonce;

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
        return this.value.equals(nonce);
    }

    @Nonnull
    @Override
    public String show() {
        return "'nonce-" + this.value.show() + "'";
    }
}
