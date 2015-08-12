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
        EOF = new Location(1, sourceText.length(), sourceText.length());
    }

    private final Location EOF;

    @Nonnull
    private Location getLocation() {
        Location location = this.hasNext() ? this.tokens[this.index].startLocation : EOF;
        assert location != null;
        return new Location(1, location.column, location.offset);
    }

    @Override
    @Nonnull
    protected ParseException createError(@Nonnull String message) {
        ParseException e = super.createError(message);
        e.location = this.getLocation();
        return e;
    }

    @Override
    @Nonnull
    protected Warning createWarning(@Nonnull String message) {
        Warning warning = super.createWarning(message);
        warning.location = this.getLocation();
        return warning;
    }
}
