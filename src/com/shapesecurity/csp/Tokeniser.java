package com.shapesecurity.csp;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.InputMismatchException;
import java.util.Scanner;
import java.util.regex.Pattern;

public class Tokeniser {
    @Nonnull
    private final Scanner scanner;
    @Nonnull
    private final ArrayList<String> tokens;

    @Nonnull
    public static String[] tokenise(@Nonnull String sourceText) throws TokeniserException {
        return new Tokeniser(sourceText).tokenise();
    }

    private static final Pattern empty = Pattern.compile("^\\s*$");
    private static final Pattern wsp = Pattern.compile("[ \t]|(?=;)");
    private static final Pattern semi = Pattern.compile(";");
    private static final Pattern directiveNamePattern = Pattern.compile("[a-zA-Z0-9-]+");
    private static final Pattern directiveValuePattern = Pattern.compile("[^\\s;,\0- \\x7F]+");

    private Tokeniser(@Nonnull String sourceText) {
        this.scanner = new Scanner(sourceText);
        this.scanner.useDelimiter(Tokeniser.wsp);
        this.tokens = new ArrayList<>();
    }

    @Nonnull
    private TokeniserException createError(@Nonnull String message) {
        return new TokeniserException(message);
    }

    private boolean eat(@Nonnull Pattern pattern) {
        if (!this.scanner.hasNext()) return false;
        try {
            this.tokens.add(this.scanner.next(pattern));
        } catch (InputMismatchException e) {
            return false;
        }
        return true;
    }

    private boolean hasNext() {
        while (this.eat(Tokeniser.empty));
        return this.scanner.hasNext();
    }

    @Nonnull
    private String[] tokenise() throws TokeniserException {
        while (this.hasNext()) {
            if (this.eat(Tokeniser.semi)) continue;
            if (!this.eat(Tokeniser.directiveNamePattern)) {
                throw this.createError("expecting directive-name but found " + this.scanner.next());
            }
            if (this.eat(Tokeniser.semi)) continue;
            while (this.hasNext()) {
                if (!this.eat(Tokeniser.directiveValuePattern)) {
                    throw this.createError("expecting directive-value but found " + this.scanner.next());
                }
                if (this.eat(Tokeniser.semi)) break;
            }
        }
        String[] tokensArray = new String[this.tokens.size()];
        return this.tokens.toArray(tokensArray);
    }

    public static class TokeniserException extends Throwable {
        public TokeniserException(@Nonnull String message) {
            super(message);
        }
    }
}
