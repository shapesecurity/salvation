package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.data.URI;

import javax.annotation.Nonnull;
import java.util.Set;

public class ReportUriDirective extends Directive<URI> {
	@Nonnull
	private static final String NAME = "report-uri";

	public ReportUriDirective(@Nonnull Set<URI> uris) {
		super(ReportUriDirective.NAME, uris);
	}

	@Nonnull
	@Override
	public Directive<URI> construct(Set<URI> newValues) {
		return new ReportUriDirective(newValues);
	}
}
