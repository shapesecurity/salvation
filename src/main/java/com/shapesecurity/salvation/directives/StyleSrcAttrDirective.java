package com.shapesecurity.salvation.directives;

import java.util.Set;

import javax.annotation.Nonnull;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

public class StyleSrcAttrDirective extends FetchDirective {
	@Nonnull
	private static final String NAME = "style-src-attr";

	public StyleSrcAttrDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
		super(StyleSrcAttrDirective.NAME, sourceExpressions);
	}

	@Nonnull
	@Override
	public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
		return new StyleSrcAttrDirective(newValues);
	}
}
