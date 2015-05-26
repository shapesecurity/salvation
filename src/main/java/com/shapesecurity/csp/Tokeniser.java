package com.shapesecurity.csp;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Tokeniser {
    @Nonnull
    private final ArrayList<String> tokens;
    @Nonnull
    private final String sourceText;
    private int index = 0;
    private final int length;

    @Nonnull
    public static String[] tokenise(@Nonnull String sourceText) throws TokeniserException {
        return new Tokeniser(sourceText).tokenise();
    }

    private static final Pattern semi = Pattern.compile(";");
    private static final Pattern directiveNamePattern = Pattern.compile("[a-zA-Z0-9-]+");
    private static final Pattern directiveValuePattern = Pattern.compile("[^;,\0- \\x7F]+");

    private static boolean isWhitespace(char ch) {
        return ch == ' ' || ch == '\t';
    }

    private Tokeniser(@Nonnull String sourceText) {
        this.tokens = new ArrayList<>();
        this.sourceText = sourceText;
        this.length = sourceText.length();
        this.eatWhitespace();
    }

    @Nonnull
    private TokeniserException createError(@Nonnull String message) {
        return new TokeniserException(message);
    }

    private boolean eat(@Nonnull Pattern pattern) {
        if (this.index >= this.length) return false;
        Matcher matcher = pattern.matcher(this.sourceText);
        if (!matcher.find(this.index) || matcher.start() != this.index) return false;
        int start = this.index;
        this.index = matcher.end();
        this.tokens.add(this.sourceText.substring(start, this.index));
        this.eatWhitespace();
        return true;
    }

    private void eatWhitespace() {
        while (this.hasNext() && Tokeniser.isWhitespace(this.sourceText.charAt(this.index))) {
            ++this.index;
        }
    }

    private boolean hasNext() {
        return this.index < this.length;
    }

    // invariant: hasNext has been called and returned true; next has not been called since; eat has not returned true since
    private String next() {
        int i = this.index;
        while (i < this.length) {
            char ch = this.sourceText.charAt(i);
            if (Tokeniser.isWhitespace(ch) || ch == ';') break;
            ++i;
        }
        return this.sourceText.substring(this.index, i);
    }

    @Nonnull
    private String[] tokenise() throws TokeniserException {
        while (this.hasNext()) {
            if (this.eat(Tokeniser.semi)) continue;
            if (!this.eat(Tokeniser.directiveNamePattern)) {
                throw this.createError("expecting directive-name but found " + this.next());
            }
            if (this.eat(Tokeniser.semi)) continue;
            while (this.hasNext()) {
                if (!this.eat(Tokeniser.directiveValuePattern)) {
                    throw this.createError("expecting directive-value but found " + this.next());
                }
                if (this.eat(Tokeniser.semi)) break;
            }
        }
        String[] tokensArray = new String[this.tokens.size()];
        return this.tokens.toArray(tokensArray);
    }

    public static class TokeniserException extends Exception {
        public TokeniserException(@Nonnull String message) {
            super(message);
        }
    }
}
