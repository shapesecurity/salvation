package com.shapesecurity.csp;

import com.shapesecurity.csp.Parser.ParseException;
import com.shapesecurity.csp.Tokeniser.TokeniserException;
import com.shapesecurity.csp.data.Policy;

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
