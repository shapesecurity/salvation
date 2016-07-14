package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.RFC7230Token;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.Set;

public class ReferrerDirective extends Directive<RFC7230Token> {
    @Nonnull private static final String NAME = "referrer";

    public ReferrerDirective(@Nonnull Set<RFC7230Token> values) {
        super(ReferrerDirective.NAME, values);
    }
    public ReferrerDirective(@Nonnull RFC7230Token v) {
        this(Collections.singleton(v));
    }

    @Nonnull @Override public Directive<RFC7230Token> construct(Set<RFC7230Token> newValues) {
        return new ReferrerDirective(newValues);
    }
}
