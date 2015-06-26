package com.shapesecurity.csp.sources;


import com.shapesecurity.csp.URI;

import javax.annotation.Nonnull;

public class KeywordSource implements SourceExpression, MatchesUri {
    @Nonnull
    private final String value;

    private KeywordSource(@Nonnull String value) {
        this.value = value;
    }

    @Nonnull
    private static String getOriginOf(@Nonnull String url) {
        // TODO: this should be implemented properly by a URL library when we stop using String for URLs
        return url;
    }

    @Override
    public boolean matchesUri(@Nonnull URI origin, @Nonnull URI uri) {
        return this == Self && origin.sameOrigin(uri);
    }

    @Nonnull
    @Override
    public String show() {
        return "'" + this.value + "'";
    }

    @Nonnull
    public static final SourceExpression Self = new KeywordSource("self");
    @Nonnull
    public static final SourceExpression UnsafeInline = new KeywordSource("unsafe-inline");
    @Nonnull
    public static final SourceExpression UnsafeEval = new KeywordSource("unsafe-eval");
    @Nonnull
    public static final SourceExpression UnsafeRedirect = new KeywordSource("unsafe-redirect");

}


