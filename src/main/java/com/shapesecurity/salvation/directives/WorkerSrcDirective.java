package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.SourceExpression;

import javax.annotation.Nonnull;
import java.util.Set;

public class WorkerSrcDirective extends NestedContextDirective {
	@Nonnull
	private static final String NAME = "worker-src";

	public WorkerSrcDirective(@Nonnull Set<SourceExpression> sourceExpressions) {
		super(WorkerSrcDirective.NAME, sourceExpressions);
	}

	@Nonnull
	@Override
	public Directive<SourceExpression> construct(Set<SourceExpression> newValues) {
		return new WorkerSrcDirective(newValues);
	}
}
