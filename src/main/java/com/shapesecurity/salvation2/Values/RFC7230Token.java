package com.shapesecurity.salvation2.Values;

import com.shapesecurity.salvation2.Constants;

import javax.annotation.Nonnull;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;

public class RFC7230Token {
	@Nonnull
	public final String value;

	private RFC7230Token(@Nonnull String value) {
		this.value = value;
	}

	public static Optional<RFC7230Token> parseRFC7230Token(String value) {
		Matcher matcher = Constants.rfc7230TokenPattern.matcher(value);
		if (matcher.find()) {
			return Optional.of(new RFC7230Token(value));
		} else {
			return Optional.empty();
		}
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof RFC7230Token)) return false;
		RFC7230Token that = (RFC7230Token) o;
		return value.equals(that.value);
	}

	@Override
	public int hashCode() {
		return Objects.hash(value);
	}

	@Override
	public String toString() {
		return this.value;
	}
}
