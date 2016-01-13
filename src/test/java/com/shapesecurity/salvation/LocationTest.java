package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.Notice;
import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.tokens.Token;
import org.junit.Test;

import java.util.ArrayList;

import static org.junit.Assert.*;

public class LocationTest extends CSPTest {

    @Test
    public void testParseExceptionLocation() {
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation.parse("script-src aaa 'none' bbb", "https://origin", notices);
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(16, notices.get(0).startLocation.column);
        assertEquals(15, notices.get(0).startLocation.offset);
        assertNotNull(notices.get(0).endLocation);
        assertEquals(1, notices.get(0).endLocation.line, 1);
        assertEquals(22, notices.get(0).endLocation.column);
        assertEquals(21, notices.get(0).endLocation.offset);
    }

    @Test public void testParseExceptionLocationReportUriEOF() {
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation.parse("report-uri", "https://origin", notices);
        assertNotNull(notices.get(0).startLocation);
        assertEquals(1, notices.get(0).startLocation.line);
        assertEquals(11, notices.get(0).startLocation.column);
        assertEquals(10, notices.get(0).startLocation.offset);
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

//    @Test public void testTokeniserExceptionLocation() {
//        try {
//            TokeniserWithLocation.tokenise("   @@@   ");
//        } catch (TokeniserException e) {
//            assertNotNull(e.location);
//            assertEquals(1, e.location.line);
//            assertEquals(4, e.location.column);
//            assertEquals(3, e.location.offset);
//            assertEquals("1:4: expecting directive-name but found @@@", e.getMessage());
//        }
//    }

//    @Test public void testTokenLocation() throws TokeniserException {
//        Token[] tokens = TokeniserWithLocation.tokenise("script-src aaa bbb");
//        assertEquals(3, tokens.length);
//        assertNotNull(tokens[0].startLocation);
//        assertEquals(1, tokens[0].startLocation.line);
//        assertEquals(1, tokens[0].startLocation.column);
//        assertEquals(0, tokens[0].startLocation.offset);
//        assertNotNull(tokens[0].endLocation);
//        assertEquals(1, tokens[0].endLocation.line);
//        assertEquals(11, tokens[0].endLocation.column);
//        assertEquals(10, tokens[0].endLocation.offset);
//        assertNotNull(tokens[1].startLocation);
//        assertEquals(1, tokens[1].startLocation.line);
//        assertEquals(12, tokens[1].startLocation.column);
//        assertEquals(11, tokens[1].startLocation.offset);
//        assertNotNull(tokens[1].endLocation);
//        assertEquals(1, tokens[1].endLocation.line);
//        assertEquals(15, tokens[1].endLocation.column);
//        assertEquals(14, tokens[1].endLocation.offset);
//        assertNotNull(tokens[2].startLocation);
//        assertEquals(1, tokens[2].startLocation.line);
//        assertEquals(16, tokens[2].startLocation.column);
//        assertEquals(15, tokens[2].startLocation.offset);
//        assertNotNull(tokens[2].endLocation);
//        assertEquals(1, tokens[2].endLocation.line);
//        assertEquals(19, tokens[2].endLocation.column);
//        assertEquals(18, tokens[2].endLocation.offset);
//    }

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
        assertEquals("1:1: media-type-list must contain at least one media-type", notice.message);
    }

    @Test public void testWarningTextWithLocation() {
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation
            .parse("script-src 'unsafe-redirect' aaa", URI.parse("https://origin"), notices);
        assertEquals(1, notices.size());
        Notice notice = notices.get(0);
        assertEquals("1:12: 'unsafe-redirect' has been removed from CSP as of version 2.0",
            notice.show());
        assertEquals("Notice: 'unsafe-redirect' has been removed from CSP as of version 2.0", notice
            .toString());
    }

    @Test public void testPotentialTyposWarnings() {
        ArrayList<Notice> notices = new ArrayList<>();
        ParserWithLocation
            .parse("script-src unsafe-redirect self none unsafe-inline unsafe-eval", URI.parse("https://origin"),
                notices);
        assertEquals(5, notices.size());
        Notice notice = notices.get(0);
        assertEquals("1:12: This host name is unusual, and likely meant to be a keyword that is missing the required quotes: 'unsafe-redirect'",
            notice.show());
        assertEquals("Notice: This host name is unusual, and likely meant to be a keyword that is missing the required quotes: 'unsafe-redirect'", notice
            .toString());
    }
}
