package com.shapesecurity.csp.tokens;

import javax.annotation.Nonnull;

public class PolicySeparatorToken extends Token {
    public PolicySeparatorToken(@Nonnull String value) {
        super(value);
    }

    @Nonnull @Override public String toJSON() {
        return super.toJSON("PolicySeparator");
    }
}
