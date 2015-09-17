package com.shapesecurity.salvation.tokens;


import javax.annotation.Nonnull;

public class DirectiveValueToken extends Token {
    public DirectiveValueToken(@Nonnull String value) {
        super(value);
    }

    @Nonnull @Override public String toJSON() {
        return super.toJSON("DirectiveValue");
    }
}
