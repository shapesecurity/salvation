package com.shapesecurity.salvation2.Values;

import com.shapesecurity.salvation2.Constants;

import javax.annotation.Nonnull;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;

public class MediaType {
	@Nonnull
	public final String type;
	@Nonnull
	public final String subtype;

	private MediaType(String type, String subtype) {
		this.type = type;
		this.subtype = subtype;
	}

	public static Optional<MediaType> parseMediaType(String value) {
		Matcher matcher = Constants.mediaTypePattern.matcher(value);
		if (matcher.find()) {
			// plugin type matching is ASCII case-insensitive
			// https://w3c.github.io/webappsec-csp/#plugin-types-post-request-check
			// Converted to .group(int) for use with TeaVM
			String type = matcher.group(1).toLowerCase(Locale.ENGLISH);
			String subtype = matcher.group(2).toLowerCase(Locale.ENGLISH);
			return Optional.of(new MediaType(type, subtype));
		}
		return Optional.empty();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		MediaType mediaType = (MediaType) o;
		return type.equals(mediaType.type) &&
				subtype.equals(mediaType.subtype);
	}

	@Override
	public int hashCode() {
		return Objects.hash(type, subtype);
	}

	@Override
	public String toString() {
		return this.type + "/" + this.subtype;
	}
}
