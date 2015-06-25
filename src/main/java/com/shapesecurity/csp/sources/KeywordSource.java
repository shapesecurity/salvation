package com.shapesecurity.csp.sources;


import javax.annotation.Nonnull;

public class KeywordSource implements SourceExpression, MatchesUrl {
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
    public boolean matchesUrl(@Nonnull String origin, @Nonnull String url) {
        return this == Self && origin.equals(getOriginOf(url));
    }

    @Nonnull
    @Override
    public String show() {
        return "'" + this.value + "'";
    }

    public static final SourceExpression Self = new KeywordSource("self");
    public static final SourceExpression UnsafeInline = new KeywordSource("unsafe-inline");
    public static final SourceExpression UnsafeEval = new KeywordSource("unsafe-eval");
    public static final SourceExpression UnsafeRedirect = new KeywordSource("unsafe-redirect");

}


