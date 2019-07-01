package com.shapesecurity.salvation.directives;

import java.util.Set;

import javax.annotation.Nonnull;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

public class ScriptSrcAttrDirective extends FetchDirective {
	@Nonnull
	private static final String NAME = "script-src-attr";

	public ScriptSrcAttrDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
		super(ScriptSrcAttrDirective.NAME, sourceExpressions);
	}

	@Nonnull
	@Override
	public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
		return new ScriptSrcAttrDirective(newValues);
	}
}
