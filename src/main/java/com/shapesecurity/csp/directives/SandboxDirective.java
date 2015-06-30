package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.directiveValues.SandboxValue;

import javax.annotation.Nonnull;
import java.util.List;

public class SandboxDirective extends Directive<SandboxValue> {
    @Nonnull
    private static final String NAME = "sandbox";

    public SandboxDirective(@Nonnull List<SandboxValue> values) {
        super(SandboxDirective.NAME, values);
    }

}
