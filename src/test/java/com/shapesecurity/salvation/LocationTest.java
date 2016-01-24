package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.Notice;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.tokens.Token;
import org.junit.Test;

import java.util.ArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class LocationTest extends CSPTest {

    @Test public void testParseExceptionLocation() {
        ArrayList<Notice> notices = new ArrayList<>();
        // TODO: fix
        ParserWithLocation.parse("script-src aaa 'none' bbb ггг", "https://origin", notices);
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(16, notices.get(0).startLocation.column);
        assertEquals(15, notices.get(0).startLocation.offset);
        assertNotNull(notices.get(0).endLocation);
        assertEquals(1, notices.get(0).endLocation.line);
        assertEquals(22, notices.get(0).endLocation.column);
        assertEquals(21, notices.get(0).endLocation.offset);
        assertNotNull(notices.get(1).startLocation);
        assertEquals(1, notices.get(1).startLocation.line);
        assertEquals(27, notices.get(1).startLocation.column);
        assertEquals(26, notices.get(1).startLocation.offset);
        assertNotNull(notices.get(1).endLocation);
        assertEquals(1, notices.get(1).endLocation.line);
        assertEquals(30, notices.get(1).endLocation.column);
        assertEquals(29, notices.get(1).endLocation.offset);
    }

        @Test public void testParseExceptionLocationReportUriEOF() {
            ArrayList<Notice> notices = new ArrayList<>();
            ParserWithLocation.parse("report-uri", "https://origin", notices);
            assertNotNull(notices.get(0).startLocation);
            assertEquals(1, notices.get(0).startLocation.line);
            assertEquals(1, notices.get(0).startLocation.column);
            assertEquals(0, notices.get(0).startLocation.offset);
            assertNotNull(notices.get(0).endLocation);
            assertEquals(1, notices.get(0).endLocation.line);
            assertEquals(11, notices.get(0).endLocation.column);
            assertEquals(10, notices.get(0).endLocation.offset);
        }

    @Test public void testParseExceptionLocationEmptyMediaTypeListEOF() {
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation.parse("plugin-types", "https://origin", notices);
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(1, notices.get(0).startLocation.column);
        assertEquals(0, notices.get(0).startLocation.offset);
        assertNotNull(notices.get(0).endLocation);
        assertEquals(1, notices.get(0).endLocation.line);
        assertEquals(13, notices.get(0).endLocation.column);
        assertEquals(12, notices.get(0).endLocation.offset);

        notices.clear();
        ParserWithLocation.parse("plugin-types aa bb", "https://origin", notices);
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(14, notices.get(0).startLocation.column);
        assertEquals(13, notices.get(0).startLocation.offset);
        assertNotNull(notices.get(0).endLocation);
        assertEquals(1, notices.get(0).endLocation.line);
        assertEquals(16, notices.get(0).endLocation.column);
        assertEquals(15, notices.get(0).endLocation.offset);
        assertNotNull(notices.get(1).startLocation);
        assertEquals(1, notices.get(1).startLocation.line);
        assertEquals(17, notices.get(1).startLocation.column);
        assertEquals(16, notices.get(1).startLocation.offset);
        assertNotNull(notices.get(1).endLocation);
        assertEquals(1, notices.get(1).endLocation.line);
        assertEquals(19, notices.get(1).endLocation.column);
        assertEquals(18, notices.get(1).endLocation.offset);

        notices.clear();
        ParserWithLocation.parse("plugin-types text/ plain       bb", "https://origin", notices);
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(14, notices.get(0).startLocation.column);
        assertEquals(13, notices.get(0).startLocation.offset);
        assertNotNull(notices.get(0).endLocation);
        assertEquals(1, notices.get(0).endLocation.line);
        assertEquals(19, notices.get(0).endLocation.column);
        assertEquals(18, notices.get(0).endLocation.offset);
        assertNotNull(notices.get(1).startLocation);
        assertEquals(1, notices.get(1).startLocation.line);
        assertEquals(20, notices.get(1).startLocation.column);
        assertEquals(19, notices.get(1).startLocation.offset);
        assertNotNull(notices.get(1).endLocation);
        assertEquals(1, notices.get(1).endLocation.line);
        assertEquals(25, notices.get(1).endLocation.column);
        assertEquals(24, notices.get(1).endLocation.offset);
        assertNotNull(notices.get(2).startLocation);
        assertEquals(1, notices.get(2).startLocation.line);
        assertEquals(32, notices.get(2).startLocation.column);
        assertEquals(31, notices.get(2).startLocation.offset);
        assertNotNull(notices.get(2).endLocation);
        assertEquals(1, notices.get(2).endLocation.line);
        assertEquals(34, notices.get(2).endLocation.column);
        assertEquals(33, notices.get(2).endLocation.offset);
    }

    @Test public void testParseExceptionLocationEmptyMediaTypeList() {
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation.parse("    plugin-types     ; script-src aaa", "https://origin", notices);
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(5, notices.get(0).startLocation.column);
        assertEquals(4, notices.get(0).startLocation.offset);
        assertNotNull(notices.get(0).endLocation);
        assertEquals(1, notices.get(0).endLocation.line);
        assertEquals(17, notices.get(0).endLocation.column);
        assertEquals(16, notices.get(0).endLocation.offset);
    }

        @Test public void testTokenLocation() {
            Token[] tokens = TokeniserWithLocation.tokenise("script-src aaa bbb");
            assertEquals(2, tokens.length);
            assertNotNull(tokens[0].startLocation);
            assertEquals(1, tokens[0].startLocation.line);
            assertEquals(1, tokens[0].startLocation.column);
            assertEquals(0, tokens[0].startLocation.offset);
            assertNotNull(tokens[0].endLocation);
            assertEquals(1, tokens[0].endLocation.line);
            assertEquals(11, tokens[0].endLocation.column);
            assertEquals(10, tokens[0].endLocation.offset);
            assertNotNull(tokens[1].startLocation);
            assertEquals(1, tokens[1].startLocation.line);
            assertEquals(12, tokens[1].startLocation.column);
            assertEquals(11, tokens[1].startLocation.offset);
            assertNotNull(tokens[1].endLocation);
            assertEquals(1, tokens[1].endLocation.line);
            assertEquals(19, tokens[1].endLocation.column);
            assertEquals(18, tokens[1].endLocation.offset);
        }

    @Test public void testWarningLocationFrameSrc() {
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation.parse("frame-src aaa", "https://origin", notices);
        assertEquals(1, notices.size());
        Notice notice = notices.get(0);
        assertNotNull(notice);
        assertNotNull(notice.startLocation);
        assertEquals(1, notice.startLocation.line);
        assertEquals(1, notice.startLocation.column);
        assertEquals(0, notice.startLocation.offset);
        assertNotNull(notice.endLocation);
        assertEquals(1, notice.endLocation.line);
        assertEquals(10, notice.endLocation.column);
        assertEquals(9, notice.endLocation.offset);
    }

    @Test public void testWarningLocationFrameAncestor() {
        // TODO: fix
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation.parse("frame-ancestors aaa bbb 'none'     ггг", "https://origin", notices);
        assertEquals(2, notices.size());
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(25, notices.get(0).startLocation.column);
        assertEquals(24, notices.get(0).startLocation.offset);
        assertNotNull(notices.get(0).endLocation);
        assertEquals(1, notices.get(0).endLocation.line);
        assertEquals(31, notices.get(0).endLocation.column);
        assertEquals(30, notices.get(0).endLocation.offset);
        assertNotNull(notices.get(1).startLocation);
        assertEquals(1, notices.get(1).startLocation.line);
        assertEquals(36, notices.get(1).startLocation.column);
        assertEquals(35, notices.get(1).startLocation.offset);
        assertNotNull(notices.get(1).endLocation);
        assertEquals(1, notices.get(1).endLocation.line);
        assertEquals(39, notices.get(1).endLocation.column);
        assertEquals(38, notices.get(1).endLocation.offset);
    }

    @Test public void testWarningLocationReferrer() {
        ArrayList<Notice> notices = new ArrayList<>();

        ParserWithLocation.parse("referrer origin", "https://origin", notices);
        assertEquals(0, notices.size());

        notices.clear();
        ParserWithLocation.parse("referrer origin no-referrer", "https://origin", notices);
        assertEquals(1, notices.size());
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(10, notices.get(0).startLocation.column);
        assertEquals(9, notices.get(0).startLocation.offset);
        assertNotNull(notices.get(0).endLocation);
        assertEquals(1, notices.get(0).endLocation.line);
        assertEquals(28, notices.get(0).endLocation.column);
        assertEquals(27, notices.get(0).endLocation.offset);

        notices.clear();
        ParserWithLocation.parse("referrer абц no-referrer", "https://origin", notices);
        assertEquals(2, notices.size());
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(1, notices.get(0).startLocation.column);
        assertEquals(0, notices.get(0).startLocation.offset);
        assertNotNull(notices.get(0).endLocation);
        assertEquals(1, notices.get(0).endLocation.line);
        assertEquals(9, notices.get(0).endLocation.column);
        assertEquals(8, notices.get(0).endLocation.offset);
        assertNotNull(notices.get(1).startLocation);
        //TODO: is second notice right??
        assertEquals(1, notices.get(1).startLocation.line);
        assertEquals(10, notices.get(1).startLocation.column);
        assertEquals(9, notices.get(1).startLocation.offset);
        assertNotNull(notices.get(1).endLocation);
        assertEquals(1, notices.get(1).endLocation.line);
        assertEquals(25, notices.get(1).endLocation.column);
        assertEquals(24, notices.get(1).endLocation.offset);
    }

    @Test public void testWarningLocationSandbox() {
        ArrayList<Notice> notices = new ArrayList<>();

        ParserWithLocation.parse("sandbox", "https://origin", notices);
        assertEquals(0, notices.size());

        notices.clear();
        ParserWithLocation.parse("sandbox origin allow-popups", "https://origin", notices);
        assertEquals(1, notices.size());
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(9, notices.get(0).startLocation.column);
        assertEquals(8, notices.get(0).startLocation.offset);
        assertNotNull(notices.get(0).endLocation);
        assertEquals(1, notices.get(0).endLocation.line);
        assertEquals(15, notices.get(0).endLocation.column);
        assertEquals(14, notices.get(0).endLocation.offset);

        notices.clear();
        ParserWithLocation.parse("sandbox allow-popups a    b", "https://origin", notices);
        assertEquals(2, notices.size());
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(22, notices.get(0).startLocation.column);
        assertEquals(21, notices.get(0).startLocation.offset);
        assertNotNull(notices.get(0).endLocation);
        assertEquals(1, notices.get(0).endLocation.line);
        assertEquals(23, notices.get(0).endLocation.column);
        assertEquals(22, notices.get(0).endLocation.offset);
        assertNotNull(notices.get(1).startLocation);
        assertEquals(1, notices.get(1).startLocation.line);
        assertEquals(27, notices.get(1).startLocation.column);
        assertEquals(26, notices.get(1).startLocation.offset);
        assertNotNull(notices.get(1).endLocation);
        assertEquals(1, notices.get(1).endLocation.line);
        assertEquals(28, notices.get(1).endLocation.column);
        assertEquals(27, notices.get(1).endLocation.offset);
    }

    @Test public void testWarningLocationUnsafeRedirect() {
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation.parse("script-src 'unsafe-redirect'", "https://origin", notices);
        assertEquals(1, notices.size());
        Notice notice = notices.get(0);
        assertNotNull(notice);
        assertNotNull(notice.startLocation);
        assertEquals(1, notice.startLocation.line);
        assertEquals(12, notice.startLocation.column);
        assertEquals(11, notice.startLocation.offset);
        assertNotNull(notice.endLocation);
        assertEquals(1, notice.endLocation.line);
        assertEquals(29, notice.endLocation.column);
        assertEquals(28, notice.endLocation.offset);
    }

    @Test public void testErrorTextWithLocation() {
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation.parse("plugin-types", "https://origin", notices);
        assertEquals(1, notices.size());
        Notice notice = notices.get(0);
        assertNotNull(notice);
        assertEquals("1:1: The media-type-list must contain at least one media-type", notice.show());
    }

    @Test public void testWarningTextWithLocation() {
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation.parse("script-src 'unsafe-redirect' aaa", URI.parse("https://origin"), notices);
        assertEquals(1, notices.size());
        Notice notice = notices.get(0);
        assertEquals("1:12: 'unsafe-redirect' has been removed from CSP as of version 2.0", notice.show());
        assertEquals("Warning: 'unsafe-redirect' has been removed from CSP as of version 2.0", notice.toString());
    }

    @Test public void testPotentialTyposWarnings() {
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation
            .parse("script-src unsafe-redirect self none unsafe-inline unsafe-eval", URI.parse("https://origin"),
                notices);
        assertEquals(5, notices.size());
        Notice notice = notices.get(0);
        assertEquals(
            "1:12: This host name is unusual, and likely meant to be a keyword that is missing the required quotes: 'unsafe-redirect'",
            notice.show());
        assertEquals(
            "Warning: This host name is unusual, and likely meant to be a keyword that is missing the required quotes: 'unsafe-redirect'",
            notice.toString());
    }
}
