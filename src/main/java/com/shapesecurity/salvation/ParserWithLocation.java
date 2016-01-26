package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.*;
import com.shapesecurity.salvation.tokens.Token;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;
import java.util.List;

public class ParserWithLocation extends Parser {

    private final Location EOF;

    // invariant: tokens will have non-null locations
    private ParserWithLocation(@Nonnull String sourceText, @Nonnull Token[] tokens, @Nonnull Origin origin,
        @Nullable Collection<Notice> warningsOut) {
        super(tokens, origin, warningsOut);
        EOF = new Location(1, sourceText.length() + 1, sourceText.length());
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull Origin origin) {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), origin, null)
            .parsePolicyAndAssertEOF();
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull Origin origin,
        @Nonnull Collection<Notice> warningsOut) {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), origin, warningsOut)
            .parsePolicyAndAssertEOF();
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull String origin) {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), URI.parse(origin), null)
            .parsePolicyAndAssertEOF();
    }

    @Nonnull public static Policy parse(@Nonnull String sourceText, @Nonnull String origin,
        @Nonnull Collection<Notice> warningsOut) {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), URI.parse(origin),
            warningsOut).parsePolicyAndAssertEOF();
    }

    @Nonnull public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull Origin origin) {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), origin, null)
            .parsePolicyListAndAssertEOF();
    }

    @Nonnull public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull String origin) {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), URI.parse(origin), null)
            .parsePolicyListAndAssertEOF();
    }

    @Nonnull public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull Origin origin,
        @Nonnull Collection<Notice> warningsOut) {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), origin, warningsOut)
            .parsePolicyListAndAssertEOF();
    }

    @Nonnull public static List<Policy> parseMulti(@Nonnull String sourceText, @Nonnull String origin,
        @Nonnull Collection<Notice> warningsOut) {
        return new ParserWithLocation(sourceText, TokeniserWithLocation.tokenise(sourceText), URI.parse(origin),
            warningsOut).parsePolicyListAndAssertEOF();
    }

    @Nonnull private Location getStartLocation(@Nullable Token token) {
        if (token == null || token.startLocation == null) {
            return new Location(1, 1, 0);
        }
        return token.startLocation;
    }

    @Nonnull private Location getEndLocation(@Nullable Token token) {
        if (token == null || token.endLocation == null) {
            return EOF;
        }
        return token.endLocation;
    }

    @Override @Nonnull protected Notice createNotice(@Nullable Token token, @Nonnull Notice.Type type, @Nonnull String message) {
        Notice notice = super.createNotice(type, message);
        notice.startLocation = this.getStartLocation(token);
        notice.endLocation = this.getEndLocation(token);
        return notice;
    }
}
