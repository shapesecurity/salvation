package com.shapesecurity.salvation.directiveValues;

import javax.annotation.Nonnull;

public class None implements SourceExpression, AncestorSource {
	@Nonnull
	public static final None INSTANCE = new None();

	private None() {
	}

	@Nonnull
	@Override
	public String show() {
		return "'none'";
	}
}
