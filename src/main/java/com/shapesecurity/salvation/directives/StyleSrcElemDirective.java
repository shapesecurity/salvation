package com.shapesecurity.salvation.directives;

import java.util.Set;

import javax.annotation.Nonnull;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

public class StyleSrcElemDirective extends FetchDirective {
	@Nonnull
	private static final String NAME = "style-src-elem";

	public StyleSrcElemDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
		super(StyleSrcElemDirective.NAME, sourceExpressions);
	}

	@Nonnull
	@Override
	public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
		return new StyleSrcElemDirective(newValues);
	}
}
