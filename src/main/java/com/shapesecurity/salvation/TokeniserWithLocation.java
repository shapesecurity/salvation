package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.Location;
import com.shapesecurity.salvation.tokens.Token;

import javax.annotation.Nonnull;
import java.util.function.Function;
import java.util.regex.Pattern;

public class TokeniserWithLocation extends Tokeniser {
	private TokeniserWithLocation(@Nonnull String sourceText) {
		super(sourceText);
	}

	@Nonnull
	public static Token[] tokenise(@Nonnull String sourceText) {
		return new TokeniserWithLocation(sourceText).tokenise();
	}

	@Nonnull
	private Location getLocation() {
		return new Location(1, this.index + 1, this.index);
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
