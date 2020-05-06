package com.shapesecurity.salvation2.Values;

import com.shapesecurity.salvation2.Utils;

import javax.annotation.Nonnull;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

public class Hash {
	@Nonnull
	public final Algorithm algorithm;
	@Nonnull
	public final String base64ValuePart;

	private Hash(Algorithm algorithm, String base64ValuePart) {
		this.algorithm = algorithm;
		this.base64ValuePart = base64ValuePart;
	}

	public static Optional<Hash> parseHash(String value) {
		String lowcaseValue = value.toLowerCase(Locale.ENGLISH);
		Algorithm algorithm;
		if (lowcaseValue.startsWith("'sha") && lowcaseValue.endsWith("'")) {
			switch (lowcaseValue.substring(4, 7)) {
				case "256":
					algorithm = Algorithm.SHA256;
					break;
				case "384":
					algorithm = Algorithm.SHA384;
					break;
				case "512":
					algorithm = Algorithm.SHA512;
					break;
				default:
					return Optional.empty();
			}
			String hash = value.substring(8, value.length() - 1);
			if (Utils.IS_BASE64_VALUE.test(hash)) {
				// Note that hashes _are_ case-sensitive, even though the grammar is not
				return Optional.of(new Hash(algorithm, hash));
			}
		}
		return Optional.empty();
	}

	@Override
	public String toString() {
		return "'" + this.algorithm.toString() + "-" + this.base64ValuePart + "'";
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Hash hash = (Hash) o;
		return algorithm == hash.algorithm &&
				base64ValuePart.equals(hash.base64ValuePart);
	}

	@Override
	public int hashCode() {
		return Objects.hash(algorithm, base64ValuePart);
	}

	public enum Algorithm {
		SHA256("sha256", 44),
		SHA384("sha384", 64),
		SHA512("sha512", 88);

		@Nonnull
		private final String value;

		@Nonnull
		public final int length;


		Algorithm(@Nonnull String value, int length) {
			this.value = value;
			this.length = length;
		}

		@Override
		public String toString() {
			return this.value;
		}
	}
}
