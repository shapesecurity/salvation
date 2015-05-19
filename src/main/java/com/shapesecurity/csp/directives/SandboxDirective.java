package com.shapesecurity.csp.directives;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.stream.Stream;

public class SandboxDirective extends Directive {
    @Nonnull
    private List<SandboxToken> sandboxTokens;

    @Nonnull
    public static final String name = "sandbox";

    public SandboxDirective(@Nonnull List<SandboxToken> sandboxTokens) {
        super(SandboxDirective.name);
        this.sandboxTokens = sandboxTokens;
    }

    @Nonnull
    @Override
    Stream<SandboxToken> values() {
        return this.sandboxTokens.stream();
    }

    @Override
    public void merge(@Nonnull Directive other) {
        if (!(other instanceof SandboxDirective)) {
            throw new Error("SandboxDirective can only be merged with other SandboxDirectives");
        }
        this.sandboxTokens = Directive.merge(this.sandboxTokens, ((SandboxDirective) other).sandboxTokens);
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof SandboxDirective)) return false;
        return this.equalsHelper((SandboxDirective) other);
    }

    @Override
    public int hashCode() {
        return this.hashCodeHelper(0x0571456E);
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
