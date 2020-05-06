package com.shapesecurity.salvation2.Values;

import com.shapesecurity.salvation2.Constants;

import javax.annotation.Nonnull;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

public class Scheme {
	@Nonnull
	public final String value;

	private Scheme(@Nonnull String value) {
		this.value = value;
	}

	public static Optional<Scheme> parseScheme(String value) {
		if (value.matches("^" + Constants.schemePart + ":$")) {
			// https://tools.ietf.org/html/rfc3986#section-3.1
			// "Although schemes are case-insensitive, the canonical form is lowercase"
			return Optional.of(new Scheme(value.substring(0, value.length() - 1).toLowerCase(Locale.ENGLISH)));
		}
		return Optional.empty();
	}

	@Override
	public String toString() {
		return this.value + ":";
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Scheme scheme = (Scheme) o;
		return value.equals(scheme.value);
	}

	@Override
	public int hashCode() {
		return Objects.hash(value);
	}
}
