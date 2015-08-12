package com.shapesecurity.csp;

import com.shapesecurity.csp.data.Location;
import com.shapesecurity.csp.tokens.Token;

import javax.annotation.Nonnull;
import java.util.function.Function;
import java.util.regex.Pattern;

public class TokeniserWithLocation extends Tokeniser {
    private TokeniserWithLocation(@Nonnull String sourceText) {
        super(sourceText);
    }

    @Nonnull
    private Location getLocation() {
        return new Location(1, this.index, this.index);
    }


    @Override
    @Nonnull
    protected TokeniserException createError(@Nonnull String message) {
        TokeniserException e = super.createError(message);
        e.location = this.getLocation();
        return e;
    }

    @Override
    protected boolean eat(@Nonnull Function<String, Token> ctor, @Nonnull Pattern pattern) {
        Location startLocation = this.getLocation();
        return super.eat(tokenText -> {
            Location endLocation = this.getLocation();
            Token token = ctor.apply(tokenText);
            token.startLocation = startLocation;
            token.endLocation = endLocation;
            return token;
        }, pattern);
    }
}
