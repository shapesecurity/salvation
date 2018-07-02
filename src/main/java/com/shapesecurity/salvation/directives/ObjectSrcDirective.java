package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class ObjectSrcDirective extends FetchDirective {
	@Nonnull
	private static final String name = "object-src";

	public ObjectSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
		super(ObjectSrcDirective.name, sourceExpressions);
	}

	@Nonnull
	@Override
	public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
		return new ObjectSrcDirective(newValues);
	}
}
