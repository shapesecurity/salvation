package com.shapesecurity.salvation2;

import javax.annotation.Nonnull;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;

public class Utils {
	public static final Predicate<String> IS_BASE64_VALUE = Pattern.compile("[a-zA-Z0-9+/\\-_]+=?=?").asPredicate();

	// https://infra.spec.whatwg.org/#split-on-ascii-whitespace
	static List<String> splitOnAsciiWhitespace(String input) {
		ArrayList<String> out = new ArrayList<>();
		for (String value : input.split("[" + Constants.WHITESPACE_CHARS + "]")) {
			if (value.isEmpty()) {
				continue;
			}
			out.add(value);
		}
		return out;
	}

	// https://infra.spec.whatwg.org/#strictly-split
	static List<String> strictlySplit(@Nonnull String s, char delim) {
		int off = 0;
		int next;
		ArrayList<String> list = new ArrayList<>();
		while ((next = s.indexOf(delim, off)) != -1) {
			list.add(s.substring(off, next));
			off = next + 1;
		}

		list.add(s.substring(off));
		return list;
	}

	static String decodeString(@Nonnull String s) {
		try {
			return URLDecoder.decode(s, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			return s;
		}
	}
}
