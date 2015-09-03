package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.data.URI;

import javax.annotation.Nonnull;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Function;

public class ReportUriDirective extends Directive<URI> {
    @Nonnull
    private static final String NAME = "report-uri";

    public ReportUriDirective(@Nonnull Set<URI> uris) {
        super(ReportUriDirective.NAME, uris);
    }

    @Nonnull
    @Override
    protected Directive<URI> construct(Set<URI> newValues) {
        return new ReportUriDirective(newValues);
    }
}
