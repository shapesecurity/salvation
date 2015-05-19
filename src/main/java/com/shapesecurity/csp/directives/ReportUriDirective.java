package com.shapesecurity.csp.directives;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.stream.Stream;

public class ReportUriDirective extends Directive {
    @Nonnull
    // @Nonempty
    // TODO: replace String with URI
    private List<URI> uris;

    @Nonnull
    private static final String name = "report-uri";

    public ReportUriDirective(@Nonnull List<URI> uris) {
        super(ReportUriDirective.name);
        this.uris = uris;
    }

    @Nonnull
    @Override
    Stream<URI> values() {
        return this.uris.stream();
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof ReportUriDirective)) return false;
        return this.equalsHelper((ReportUriDirective) other);
    }

    @Override
    public int hashCode() {
        return this.hashCodeHelper(0xF5C68166);
    }

    @Override
    public void merge(@Nonnull Directive other) {
        if (!(other instanceof ReportUriDirective)) {
            throw new Error("ReportUriDirective can only be merged with other ReportUriDirectives");
        }
        this.uris = Directive.merge(this.uris, ((ReportUriDirective) other).uris);
    }

    public static class URI implements DirectiveValue {
        @Nonnull
        private final String value;

        public URI(@Nonnull String value) {
            this.value = value;
        }

        @Nonnull
        @Override
        public String show() {
            return this.value;
        }
    }
}
