package com.shapesecurity.salvation.tokens;

import javax.annotation.Nonnull;

public class SubDirectiveValueToken extends Token {
    public SubDirectiveValueToken(@Nonnull String value) {
        super(value);
    }

    @Nonnull @Override public String toJSON() {
        return super.toJSON("SubDirectiveValue");
    }
}
