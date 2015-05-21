package com.shapesecurity.csp.directives;

import javax.annotation.Nonnull;
import java.util.List;

public class SandboxDirective extends Directive<SandboxDirective.SandboxToken> {
    @Nonnull
    private static final String NAME = "sandbox";

    public SandboxDirective(@Nonnull List<SandboxToken> values) {
        super(SandboxDirective.NAME, values);
    }

    public static class SandboxToken implements DirectiveValue {
        @Nonnull
        private final String value;

        public SandboxToken(@Nonnull String value) {
            this.value = value;
        }

        @Nonnull
        @Override
        public String show() {
            return this.value;
        }

        @Override
        public int hashCode() {
            return this.value.hashCode();
        }

        @Override
        public boolean equals(@Nonnull Object obj) {
            return obj instanceof SandboxToken && ((SandboxToken) obj).value.equals(this.value);
        }
    }
}
