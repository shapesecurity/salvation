package com.shapesecurity.csp.tokens;


import javax.annotation.Nonnull;

public class DirectiveSeparatorToken extends Token {
    public DirectiveSeparatorToken(@Nonnull String value) {
        super(value);
    }

    @Nonnull
    @Override
    public String toJSON() {
        return super.toJSON("DirectiveSeparator");
    }
}
