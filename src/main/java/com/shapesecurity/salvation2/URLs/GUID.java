package com.shapesecurity.salvation2.URLs;

import com.shapesecurity.salvation2.Constants;

import javax.annotation.Nonnull;
import java.util.Optional;
import java.util.regex.Matcher;

public class GUID extends URLWithScheme {
	// See https://url.spec.whatwg.org/#example-url-components
	public GUID(@Nonnull String scheme, @Nonnull String value) {
		super(scheme, null, null, value);
	}

	public static Optional<GUID> parseGUID(String value) {
		Matcher matcher = Constants.schemePattern.matcher(value);
		if (!matcher.find()) {
			return Optional.empty();
		}
		String scheme = matcher.group("scheme");
		scheme = scheme.substring(0, scheme.length() - 1);  // + 1 for the trailing ":"
		return Optional.of(new GUID(scheme, value.substring(scheme.length() + 1)));
	}
}
