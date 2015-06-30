package com.shapesecurity.csp.directives;

import com.shapesecurity.csp.data.URI;

import javax.annotation.Nonnull;
import java.util.List;

public class ReportUriDirective extends Directive<URI> {
    @Nonnull
    private static final String NAME = "report-uri";

    public ReportUriDirective(@Nonnull List<URI> uris) {
        super(ReportUriDirective.NAME, uris);
    }
}
