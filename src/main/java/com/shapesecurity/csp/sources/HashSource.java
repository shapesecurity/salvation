package com.shapesecurity.csp.sources;

import com.shapesecurity.csp.Base64Value;
import com.shapesecurity.csp.Show;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class HashSource implements SourceExpression {
    @Nonnull
    private final HashAlgorithm algorithm;
    @Nonnull
    private final Base64Value value;

    public HashSource(@Nonnull HashAlgorithm algorithm, @Nonnull Base64Value value) {
        this.algorithm = algorithm;
        this.value = value;
    }

    @Nonnull
    @Override
    public String show() {
        return "'" + this.algorithm.show() + "-" + this.value.show() + "'";
    }


    @Override
    public boolean equals(@Nullable Object other) {
        if (other == null || !(other instanceof HashSource)) return false;
        return this.algorithm.equals(((HashSource) other).algorithm) &&
            this.value.equals(((HashSource) other).value);
    }

    @Override
    public int hashCode() {
        return (this.algorithm.getHashCode() ^ 0xFE608B8F) ^ (this.value.hashCode() ^ 0x01D77E94);
    }


    public enum HashAlgorithm implements Show {
        SHA256("sha256"),
        SHA384("sha384"),
        SHA512("sha512");

        @Nonnull
        private final String value;

        HashAlgorithm(@Nonnull String value) {
            this.value = value;
        }

        public int getHashCode() {
            return this.value.hashCode();
        }

        @Nonnull
        @Override
        public String show() {
            return this.value;
        }
    }
}