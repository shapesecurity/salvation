package com.shapesecurity.salvation;

import com.shapesecurity.salvation.Parser.ParseException;
import com.shapesecurity.salvation.Tokeniser.TokeniserException;

import com.shapesecurity.salvation.data.URI;
import com.shapesecurity.salvation.data.Warning;
import com.shapesecurity.salvation.tokens.Token;
import org.junit.Test;

import java.util.ArrayList;

import static org.junit.Assert.*;

public class LocationTest extends CSPTest {

    @Test
    public void testParseExceptionLocation() throws TokeniserException {
        try {
            ParserWithLocation.parse("script-src aaa 'none' bbb", "https://origin");
        } catch (ParseException e) {
            assertNotNull(e.startLocation);
            assertEquals(1, e.startLocation.line);
            assertEquals(16, e.startLocation.column);
            assertEquals(15, e.startLocation.offset);
            assertNotNull(e.endLocation);
            assertEquals(1, e.endLocation.line, 1);
            assertEquals(22, e.endLocation.column);
            assertEquals(21, e.endLocation.offset);
            return;
        }

        fail();
    }

    @Test public void testParseExceptionLocationReportUriEOF() throws TokeniserException {
        try {
            ParserWithLocation.parse("report-uri", "https://origin");
        } catch (ParseException e) {
            assertNotNull(e.startLocation);
            assertEquals(1, e.startLocation.line);
            assertEquals(11, e.startLocation.column);
            assertEquals(10, e.startLocation.offset);
            assertNotNull(e.endLocation);
            assertEquals(1, e.endLocation.line);
            assertEquals(11, e.endLocation.column);
            assertEquals(10, e.endLocation.offset);
            return;
        }
        fail();
    }

    @Test public void testParseExceptionLocationEmptyMediaTypeListEOF() throws TokeniserException {
        try {
            ParserWithLocation.parse("plugin-types", "https://origin");
        } catch (ParseException e) {
            assertNotNull(e.startLocation);
            assertEquals(1, e.startLocation.line);
            assertEquals(1, e.startLocation.column);
            assertEquals(0, e.startLocation.offset);
            assertNotNull(e.endLocation);
            assertEquals(1, e.endLocation.line);
            assertEquals(13, e.endLocation.column);
            assertEquals(12, e.endLocation.offset);
            return;
        }
        fail();
    }

    @Test public void testParseExceptionLocationEmptyMediaTypeList() throws TokeniserException {
        try {
            ParserWithLocation.parse("    plugin-types     ; script-src aaa", "https://origin");
        } catch (ParseException e) {
            assertNotNull(e.startLocation);
            assertEquals(1, e.startLocation.line);
            assertEquals(5, e.startLocation.column);
            assertEquals(4, e.startLocation.offset);
            assertNotNull(e.endLocation);
            assertEquals(1, e.endLocation.line);
            assertEquals(17, e.endLocation.column);
            assertEquals(16, e.endLocation.offset);
            return;
        }
        fail();
    }

    @Test public void testTokeniserExceptionLocation() {
        try {
            TokeniserWithLocation.tokenise("   @@@   ");
        } catch (TokeniserException e) {
            assertNotNull(e.location);
            assertEquals(1, e.location.line);
            assertEquals(4, e.location.column);
            assertEquals(3, e.location.offset);
            assertEquals("1:4: expecting directive-name but found @@@", e.getMessage());
        }
    }

    @Test public void testTokenLocation() throws TokeniserException {
        Token[] tokens = TokeniserWithLocation.tokenise("script-src aaa bbb");
        assertEquals(3, tokens.length);
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
        assertEquals(15, tokens[1].endLocation.column);
        assertEquals(14, tokens[1].endLocation.offset);
        assertNotNull(tokens[2].startLocation);
        assertEquals(1, tokens[2].startLocation.line);
        assertEquals(16, tokens[2].startLocation.column);
        assertEquals(15, tokens[2].startLocation.offset);
        assertNotNull(tokens[2].endLocation);
        assertEquals(1, tokens[2].endLocation.line);
        assertEquals(19, tokens[2].endLocation.column);
        assertEquals(18, tokens[2].endLocation.offset);
    }

    @Test public void testWarningLocationFrameSrc() throws ParseException, TokeniserException {
        ArrayList<Warning> warnings = new ArrayList<>();
        ParserWithLocation.parse("frame-src aaa", "https://origin", warnings);
        assertEquals(1, warnings.size());
        Warning warning = warnings.get(0);
        assertNotNull(warning);
        assertNotNull(warning.startLocation);
        assertEquals(1, warning.startLocation.line);
        assertEquals(1, warning.startLocation.column);
        assertEquals(0, warning.startLocation.offset);
        assertNotNull(warning.endLocation);
        assertEquals(1, warning.endLocation.line);
        assertEquals(10, warning.endLocation.column);
        assertEquals(9, warning.endLocation.offset);
    }

    @Test public void testWarningLocationUnsafeRedirect()
        throws ParseException, TokeniserException {
        ArrayList<Warning> warnings = new ArrayList<>();
        ParserWithLocation.parse("script-src 'unsafe-redirect'", "https://origin", warnings);
        assertEquals(1, warnings.size());
        Warning warning = warnings.get(0);
        assertNotNull(warning);
        assertNotNull(warning.startLocation);
        assertEquals(1, warning.startLocation.line);
        assertEquals(12, warning.startLocation.column);
        assertEquals(11, warning.startLocation.offset);
        assertNotNull(warning.endLocation);
        assertEquals(1, warning.endLocation.line);
        assertEquals(29, warning.endLocation.column);
        assertEquals(28, warning.endLocation.offset);
    }

    @Test public void testErrorTextWithLocation() throws ParseException, TokeniserException {
        try {
            ParserWithLocation.parse("plugin-types", "https://origin");
        } catch (ParseException e) {
            assertEquals("1:1: media-type-list must contain at least one media-type",
                e.getMessage());
            return;
        }
        fail();
    }

    @Test public void testWarningTextWithLocation() throws ParseException, TokeniserException {
        ArrayList<Warning> warnings = new ArrayList<>();
        ParserWithLocation
            .parse("script-src 'unsafe-redirect' aaa", URI.parse("https://origin"), warnings);
        assertEquals(1, warnings.size());
        Warning warning = warnings.get(0);
        assertEquals("1:12: 'unsafe-redirect' has been removed from CSP as of version 2.0",
            warning.show());
        assertEquals("Warning: 'unsafe-redirect' has been removed from CSP as of version 2.0", warning.toString());
    }

}
