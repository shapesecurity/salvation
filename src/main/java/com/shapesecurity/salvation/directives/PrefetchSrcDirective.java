package com.shapesecurity.salvation.directives;

import java.util.Set;

import javax.annotation.Nonnull;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

public class PrefetchSrcDirective extends FetchDirective {
	@Nonnull
	private static final String NAME = "prefetch-src";

	public PrefetchSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
		super(PrefetchSrcDirective.NAME, sourceExpressions);
	}

	@Nonnull
	@Override
	public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
		return new PrefetchSrcDirective(newValues);
	}
}
