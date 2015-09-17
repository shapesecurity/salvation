package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SandboxValue;

import javax.annotation.Nonnull;
import java.util.Set;

public class SandboxDirective extends Directive<SandboxValue> {
    @Nonnull private static final String NAME = "sandbox";

    public SandboxDirective(@Nonnull Set<SandboxValue> values) {
        super(SandboxDirective.NAME, values);
    }

    @Nonnull @Override public Directive<SandboxValue> construct(Set<SandboxValue> newValues) {
        return new SandboxDirective(newValues);
    }
}
