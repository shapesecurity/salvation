package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.URI;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.stream.Stream;

public class ReportUriDirective extends Directive<URI> {
    @Nonnull
    private static final String NAME = "report-uri";

    public ReportUriDirective(@Nonnull List<URI> uris) {
        super(ReportUriDirective.NAME, uris);
    }
}
