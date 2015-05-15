package com.shapesecurity.csp.sources;


import javax.annotation.Nonnull;

public class KeywordSource implements SourceExpression {
    @Nonnull
    private final String value;

    private KeywordSource(@Nonnull String value) {
        this.value = value;
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


