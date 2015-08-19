package com.shapesecurity.csp;

import com.shapesecurity.csp.data.*;
import com.shapesecurity.csp.tokens.Token;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;

public class ParserWithLocation extends Parser {

    @Nonnull
    public static Policy parse(@Nonnull String sourceText, @Nonnull Origin origin) throws ParseException, Tokeniser.TokeniserException {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), origin, null).parsePrivate();
    }

    @Nonnull
    public static Policy parse(@Nonnull String sourceText, @Nonnull Origin origin, @Nonnull Collection<Warning> warningsOut) throws ParseException, Tokeniser.TokeniserException {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), origin, warningsOut).parsePrivate();
    }

    @Nonnull
    public static Policy parse(@Nonnull String sourceText, @Nonnull String origin) throws ParseException, Tokeniser.TokeniserException {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), URI.parse(origin), null).parsePrivate();
    }

    @Nonnull
    public static Policy parse(@Nonnull String sourceText, @Nonnull String origin, @Nonnull Collection<Warning> warningsOut) throws ParseException, Tokeniser.TokeniserException {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), URI.parse(origin), warningsOut).parsePrivate();
    }

    // invariant: tokens will have non-null locations
    private ParserWithLocation(@Nonnull String sourceText, @Nonnull Token[] tokens, @Nonnull Origin origin, @Nullable Collection<Warning> warningsOut) {
        super(tokens, origin, warningsOut);
        EOF = new Location(1, sourceText.length() + 1, sourceText.length());
    }

    private final Location EOF;

    @Nullable
    private Token getCurrentToken() {
        return this.index <= this.tokens.length && this.index > 0 ? this.tokens[this.index - 1] : null;
    }

    @Nonnull
    private Location getStartLocation() {
        Token currentToken = this.getCurrentToken();
        if (currentToken == null || currentToken.startLocation == null) {
            return new Location(1, 1, 0);
        }
        return currentToken.startLocation;
    }

    @Nonnull
    private Location getEndLocation() {
        Token currentToken = this.getCurrentToken();
        if (currentToken == null || currentToken.endLocation == null) {
            return EOF;
        }
        return currentToken.endLocation;
    }

    @Override
    @Nonnull
    protected ParseException createUnexpectedEOF(@Nonnull String message) {
        ParseException e = super.createError(message);
        e.startLocation = EOF;
        e.endLocation = EOF;
        return e;
    }

    @Override
    @Nonnull
    protected ParseException createError(@Nonnull String message) {
        ParseException e = super.createError(message);
        e.startLocation = this.getStartLocation();
        e.endLocation = this.getEndLocation();
        return e;
    }

    @Override
    @Nonnull
    protected Warning createWarning(@Nonnull String message) {
        Warning warning = super.createWarning(message);
        warning.startLocation = this.getStartLocation();
        warning.endLocation = this.getEndLocation();
        return warning;
    }
}
