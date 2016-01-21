package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.Notice;
import com.shapesecurity.salvation.data.Policy;

import javax.annotation.Nonnull;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.fail;

public class CSPTest {

    @Nonnull
    protected static Policy parse(@Nonnull String policy) {
        return Parser.parse(policy, "http://example.com");
    }

    @Nonnull
    protected static Policy parseWithNotices(@Nonnull String policy, @Nonnull ArrayList<Notice> notices) {
        return Parser.parse(policy, "http://example.com", notices);
    }

    @Nonnull
    protected static List<Policy> parseMultiWithNotices(@Nonnull String policy, @Nonnull ArrayList<Notice> notices) {
        return Parser.parseMulti(policy, "http://example.com", notices);
    }

    @Nonnull
    protected static String parseAndShow(@Nonnull String value) {
        return parse(value).show();
    }

    protected static void failsToParse(String policy) {
        try {
            parse(policy);
        } catch (IllegalArgumentException ignored) {
            return;
        }
        fail();
    }
}
