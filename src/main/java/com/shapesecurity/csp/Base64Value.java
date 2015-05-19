package com.shapesecurity.csp;

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
        for (int i = 0; i < chars.length - 2; i++) {
            if (!isBase64Chars(chars[i])) {
                throw new IllegalArgumentException("invalid base64 string (illegal characters): " + value);
            }
        }
        for (int i = chars.length - 2; i < chars.length; i++) {
            if (!isBase64Chars(chars[i]) && chars[i] != '=') {
                throw new IllegalArgumentException("invalid base64 string padding (illegal characters): " + value);
            }
            if(i == chars.length - 1 && chars[i - 1] == '=' && chars[i] != '=') {
                throw new IllegalArgumentException("invalid base64 string padding (illegal last character): " + value);
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
        if (other == null || !(other instanceof Base64Value)) return false;
        return this.value.equals(((Base64Value) other).value);
    }

    @Override
    public int hashCode() {
        return this.value.hashCode();
    }

    @Nonnull
    @Override
    public String show() {
        return this.value.replace('-', '+').replace('_', '/');
    }

    public class IllegalArgumentException extends Exception {
        IllegalArgumentException(String message) {
            super(message);
        }
    }
}