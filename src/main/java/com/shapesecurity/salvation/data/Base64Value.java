package com.shapesecurity.salvation.data;

import com.shapesecurity.salvation.interfaces.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64Value implements Show {
    @Nonnull public final String value;

    @Nonnull private final byte[] decoded;

    public Base64Value(@Nonnull String value) {
        Base64Value.validate(value);
        this.value = value;
        this.decoded = Base64.getDecoder().decode(value);
    }

    public static void validate(String value) throws IllegalArgumentException {
        byte[] chars = value.getBytes(StandardCharsets.US_ASCII);

        if (chars.length % 4 != 0) {
            throw new IllegalArgumentException(
                "Invalid base64-value (should be multiple of 4 bytes: " + chars.length
                    + "). Consider using RFC4648 compliant base64 encoding implementation");
        }

        int i;
        for (i = 0; i < chars.length; i++) {
            if (chars[i] == '=') {
                break;
            }
            if (!isBase64Char(chars[i])) {
                throw new IllegalArgumentException(
                    "Invalid base64-value (characters are not in the base64-value grammar). Consider using RFC4648 compliant base64 encoding implementation");
            }
        }
        if (i < chars.length - 2) {
            throw new IllegalArgumentException(
                "Invalid base64-value (bad padding). Consider using RFC4648 compliant base64 encoding implementation");
        }
        for (; i < chars.length; i++) {
            if (chars[i] != '=') {
                throw new IllegalArgumentException(
                    "Invalid base64-value padding (illegal characters). Consider using RFC4648 compliant base64 encoding implementation");
            }
        }

        if (chars.length < 4) {
            throw new IllegalArgumentException(
                "Invalid base64-value (too short: " + chars.length + ")");
        }
    }

    public static boolean isBase64Char(byte ch) {
        return '0' <= ch && ch <= '9' ||
            'A' <= ch && ch <= 'Z' ||
            'a' <= ch && ch <= 'z' ||
            ch == '+' || ch == '/';
    }

    public int size() {
        return this.decoded.length;
    }

    public ByteBuffer decodedBytes() {
        return ByteBuffer.wrap(this.decoded).asReadOnlyBuffer();
    }

    @Override public boolean equals(@Nullable Object other) {
        return !(other == null || !(other instanceof Base64Value)) && this.value
            .equals(((Base64Value) other).value);
    }

    @Override public int hashCode() {
        return this.value.hashCode();
    }

    @Nonnull @Override public String show() {
        return this.value;
    }
}
