package com.shapesecurity.salvation;

import com.shapesecurity.salvation.Parser.ParseException;
import com.shapesecurity.salvation.Tokeniser.TokeniserException;
import com.shapesecurity.salvation.data.Policy;

import javax.annotation.Nonnull;

import static org.junit.Assert.*;

public class CSPTest {

    @Nonnull
    protected static Policy parse(@Nonnull String policy)
        throws ParseException, TokeniserException {
        return Parser.parse(policy, "http://example.com");
    }

    @Nonnull
    protected static String parseAndShow(@Nonnull String value) throws ParseException, TokeniserException {
        return parse(value).show();
    }

    protected static void failsToParse(String policy) {
        try {
            parse(policy);
        } catch (ParseException | TokeniserException | IllegalArgumentException ignored) {
            return;
        }
        fail();
    }
}
