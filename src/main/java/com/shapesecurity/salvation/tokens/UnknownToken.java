package com.shapesecurity.salvation.tokens;

import javax.annotation.Nonnull;

public class UnknownToken extends Token {
	public UnknownToken(@Nonnull String value) {
		super(value);
	}

	@Nonnull
	@Override
	public String toJSON() {
		return super.toJSON("UnknownToken");
	}
}
