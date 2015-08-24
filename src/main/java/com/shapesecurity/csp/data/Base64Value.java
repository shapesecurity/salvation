package com.shapesecurity.csp.data;

import com.shapesecurity.csp.interfaces.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class Base64Value implements Show {
    @Nonnull
    private final String value;

    public Base64Value(@Nonnull String value) throws IllegalArgumentException {
        char[] chars = value.toCharArray();
        // TODO: loosen this restriction
        if (chars.length % 4 != 0) {
            throw new IllegalArgumentException("invalid base64 string (should be multiple of 4 bytes: " + chars.length + "): " + value);
        }

        int i;
        for (i = 0; i < chars.length; i++) {
            if (chars[i] == '=') {
                break;
            }
            if (!isBase64Chars(chars[i])) {
                throw new IllegalArgumentException("invalid base64 string (illegal characters): " + value);
            }
        }
        if (i < chars.length - 2) {
            throw new IllegalArgumentException("invalid base64 string (illegal characters): " + value);
        }
        for (; i < chars.length; i++) {
            if (chars[i] != '=') {
                throw new IllegalArgumentException("invalid base64 string padding (illegal characters): " + value);
            }
        }
        this.value = value;
    }

    private boolean isBase64Chars(char ch) {
        return '0' <= ch && ch <= '9' ||
            'A' <= ch && ch <= 'Z' ||
            'a' <= ch && ch <= 'z' ||
            ch == '/' || ch == '+' ||
            ch == '-' || ch == '_';
    }

    @Override
    public boolean equals(@Nullable Object other) {
        return !(other == null || !(other instanceof Base64Value)) && this.value.equals(((Base64Value) other).value);
    }

    @Override
    public int hashCode() {
        return this.value.hashCode();
    }

    @Nonnull
    @Override
    public String show() {
        // TODO: figure out if we should do this
        // return this.value.replace('-', '+').replace('_', '/');
        return this.value;
    }
}