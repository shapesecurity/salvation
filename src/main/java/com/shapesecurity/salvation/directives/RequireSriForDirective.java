package com.shapesecurity.salvation.directives;

import com.shapesecurity.salvation.directiveValues.RFC7230Token;

import javax.annotation.Nonnull;
import java.util.Set;

public class RequireSriForDirective extends Directive<RFC7230Token> {
	@Nonnull
	private static final String NAME = "require-sri-for";

	public RequireSriForDirective(@Nonnull Set<RFC7230Token> values) {
		super(RequireSriForDirective.NAME, values);
	}

	@Nonnull
	@Override
	public Directive<RFC7230Token> construct(Set<RFC7230Token> newValues) {
		return new RequireSriForDirective(newValues);
	}
}
