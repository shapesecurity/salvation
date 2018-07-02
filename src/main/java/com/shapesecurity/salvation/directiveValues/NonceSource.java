package com.shapesecurity.salvation.directiveValues;

import com.shapesecurity.salvation.data.Base64Value;
import com.shapesecurity.salvation.interfaces.MatchesNonce;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;

public class NonceSource implements SourceExpression, MatchesNonce {
	@Nonnull
	private final String value;

	public NonceSource(@Nonnull String value) {
		this.value = value;
	}

	public List<String> validationErrors() {
		List<String> errors = new ArrayList<>();
		Base64Value base64Value;
		try {
			// convert url-safe base64 to RFC4648 base64
			String safeValue = this.value.replace('-', '+').replace('_', '/');
			base64Value = new Base64Value(safeValue);
			// warn if value is not RFC4648
			if ((this.value.contains("-") || this.value.contains("_")) &&
					(this.value.contains("+") || this.value.contains("/"))) {
				errors.add(
						"Invalid base64-value. Must use either RFC4648 \"base64\" characters (including + and /) or RFC4648 \"base64url\" characters (including - and _), but not both.");
			}
		} catch (IllegalArgumentException e) {
			errors.add(e.getMessage());
			return errors;
		}
		if (base64Value.size() < 16) {
			errors.add("CSP specification recommends nonce-value to be at least 128 bits long (before encoding).");
		}
		return errors;
	}

	@Override
	public boolean equals(@Nullable Object other) {
		if (other == null || !(other instanceof NonceSource)) {
			return false;
		}
		return this.value.equals(((NonceSource) other).value);
	}

	@Override
	public int hashCode() {
		return this.value.hashCode();
	}

	public boolean matchesNonce(@Nonnull String nonce) {
		return this.value.equals(nonce);
	}

	@Nonnull
	@Override
	public String show() {
		return "'nonce-" + this.value + "'";
	}
}
