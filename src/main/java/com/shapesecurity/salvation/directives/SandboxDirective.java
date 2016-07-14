package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.RFC7230Token;

import javax.annotation.Nonnull;
import java.util.Set;

public class SandboxDirective extends Directive<RFC7230Token> {
    @Nonnull private static final String NAME = "sandbox";

    public SandboxDirective(@Nonnull Set<RFC7230Token> values) {
        super(SandboxDirective.NAME, values);
    }

    @Nonnull @Override public Directive<RFC7230Token> construct(Set<RFC7230Token> newValues) {
        return new SandboxDirective(newValues);
    }
}
