package com.shapesecurity.csp.data;

import com.shapesecurity.csp.interfaces.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64Value implements Show {
    @Nonnull private final String value;

    public Base64Value(@Nonnull String value) {
        this.value = value;
    }

    public void validate() throws IllegalArgumentException {

        byte[] chars = value.getBytes(StandardCharsets.US_ASCII);

        if (chars.length % 4 != 0) {
            throw new IllegalArgumentException(
                "Invalid base64 string (should be multiple of 4 bytes: " + chars.length + "): "
                    + value);
        }

        int i;
        for (i = 0; i < chars.length; i++) {
            if (chars[i] == '=') {
                break;
            }
            if (!isBase64Chars(chars[i])) {
                throw new IllegalArgumentException(
                    "Invalid base64 string (illegal characters): " + value);
            }
        }
        if (i < chars.length - 2) {
            throw new IllegalArgumentException(
                "Invalid base64 string (illegal characters): " + value);
        }
        for (; i < chars.length; i++) {
            if (chars[i] != '=') {
                throw new IllegalArgumentException(
                    "Invalid base64 string padding (illegal characters): " + value);
            }
        }

        byte[] bytes = Base64.getDecoder().decode(chars);
        if (bytes.length < 16) {
            throw new IllegalArgumentException(
                "CSP specification recommends nonce-value to be at least 128 bits long (before encoding).");
        }
    }

    private boolean isBase64Chars(byte ch) {
        return '0' <= ch && ch <= '9' ||
            'A' <= ch && ch <= 'Z' ||
            'a' <= ch && ch <= 'z' ||
            ch == '/' || ch == '+' ||
            ch == '-' || ch == '_';
    }

    @Override public boolean equals(@Nullable Object other) {
        return !(other == null || !(other instanceof Base64Value)) && this.value
            .equals(((Base64Value) other).value);
    }

    @Override public int hashCode() {
        return this.value.hashCode();
    }

    @Nonnull @Override public String show() {
        // TODO: figure out if we should do this
        // return this.value.replace('-', '+').replace('_', '/');
        return this.value;
    }
}
