package com.shapesecurity.salvation2.Values;

import com.shapesecurity.salvation2.Utils;

import javax.annotation.Nonnull;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

public class Nonce {
	@Nonnull
	public final String base64ValuePart;

	private Nonce(@Nonnull String base64Valuepart) {
		this.base64ValuePart = base64Valuepart;
	}

	public static Optional<Nonce> parseNonce(String value) {
		String lowcaseValue = value.toLowerCase(Locale.ENGLISH);
		if (lowcaseValue.startsWith("'nonce-") && lowcaseValue.endsWith("'")) {
			String nonce = value.substring(7, value.length() - 1);
			if (Utils.IS_BASE64_VALUE.test(nonce)) {
				// Note that nonces _are_ case-sensitive, even though the grammar is not
				return Optional.of(new Nonce(nonce));
			}
		}
		return Optional.empty();
	}

	@Override
	public String toString() {
		return "'nonce-" + base64ValuePart + "'";
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Nonce nonce = (Nonce) o;
		return base64ValuePart.equals(nonce.base64ValuePart);
	}

	@Override
	public int hashCode() {
		return Objects.hash(base64ValuePart);
	}
}
