package com.shapesecurity.csp.sources;


import com.shapesecurity.csp.Origin;
import com.shapesecurity.csp.URI;

import javax.annotation.Nonnull;

public class KeywordSource implements SourceExpression, MatchesUri {
    @Nonnull
    private final String value;

    private KeywordSource(@Nonnull String value) {
        this.value = value;
    }

    @Override
    public boolean matchesUri(@Nonnull Origin origin, @Nonnull URI uri) {
        return this == Self && origin.equals(uri);
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


