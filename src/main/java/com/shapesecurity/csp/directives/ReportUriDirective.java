package com.shapesecurity.csp.directives;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.stream.Stream;

public class ReportUriDirective extends Directive<ReportUriDirective.URI> {
    @Nonnull
    private static final String NAME = "report-uri";

    public ReportUriDirective(@Nonnull List<URI> uris) {
        super(ReportUriDirective.NAME, uris);
    }

    public static class URI implements DirectiveValue {
        @Nonnull
        private final String value;

        public URI(@Nonnull String value) {
            this.value = value;
        }

        @Override
        public int hashCode() {
            return this.value.hashCode();
        }

        @Override
        public boolean equals(@Nullable Object other) {
            if (other == null || !(other instanceof URI)) return false;
            return this.value.equals(((URI) other).value);
        }

        @Nonnull
        @Override
        public String show() {
            return this.value;
        }
    }
}
