package com.shapesecurity.salvation.directives;

import java.util.Set;

import javax.annotation.Nonnull;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

public class ScriptSrcElemDirective extends FetchDirective {
	@Nonnull
	private static final String NAME = "script-src-elem";

	public ScriptSrcElemDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
		super(ScriptSrcElemDirective.NAME, sourceExpressions);
	}

	@Nonnull
	@Override
	public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
		return new ScriptSrcElemDirective(newValues);
	}
}
