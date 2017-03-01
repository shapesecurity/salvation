package com.shapesecurity.salvation;

import com.shapesecurity.salvation.data.Location;
import com.shapesecurity.salvation.tokens.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Tokeniser {
    private static final Pattern WSP = Pattern.compile("[ \t]+");
    private static final Pattern NotWSP = Pattern.compile("[^ \t]+");
    private static final Pattern directiveSeparator = Pattern.compile(";");
    private static final Pattern policySeparator = Pattern.compile(",");
    private static final Pattern directiveNamePattern = Pattern.compile("[a-zA-Z0-9-]+");
    private static final Pattern directiveValuePattern = Pattern.compile("[ \\t!-+--:<-~]+");
    private static final Pattern notSeparator = Pattern.compile("[^;,]+");
    @Nonnull protected ArrayList<Token> tokens;
    @Nonnull protected final String sourceText;
    protected final int length;
    protected int index = 0;

    protected Tokeniser(@Nonnull String sourceText) {
        this.tokens = new ArrayList<>();
        this.sourceText = sourceText;
        this.length = sourceText.length();
    }

    @Nonnull public static Token[] tokenise(@Nonnull String sourceText) {
        return new Tokeniser(sourceText).tokenise();
    }

    private static boolean isWhitespace(char ch) {
        return ch == ' ' || ch == '\t';
    }

    protected boolean eat(@Nonnull Function<String, Token> ctor, @Nonnull Pattern pattern) {
        if (this.index >= this.length)
            return false;
        Matcher matcher = pattern.matcher(this.sourceText);
        if (!matcher.find(this.index) || matcher.start() != this.index)
            return false;
        int start = this.index;
        this.index = matcher.end();
        this.tokens.add(ctor.apply(this.sourceText.substring(start, this.index)));
        return true;
    }

    private boolean eatSeparator() {
        return this.eat(DirectiveSeparatorToken::new, Tokeniser.directiveSeparator) ||
            this.eat(PolicySeparatorToken::new, Tokeniser.policySeparator);
    }

    private boolean eatDirectiveName() {
        return this.eat(DirectiveNameToken::new, Tokeniser.directiveNamePattern);
    }

    private boolean eatDirectiveValue() {
        return this.eat(DirectiveValueToken::new, Tokeniser.directiveValuePattern);
    }

    private boolean eatUntilSeparator() {
        return this.eat(UnknownToken::new, Tokeniser.notSeparator);
    }

    private boolean eatSingleWhitespace() {
        if (this.hasNext() && Tokeniser.isWhitespace(this.sourceText.charAt(this.index))) {
            ++this.index;
            return true;
        }
        return false;
    }

    private void eatWhitespace() {
        while (this.hasNext() && Tokeniser.isWhitespace(this.sourceText.charAt(this.index))) {
            ++this.index;
        }
    }

    private boolean hasNext() {
        return this.index < this.length;
    }

    @Nonnull protected Token[] tokenise() {
        while (this.hasNext()) {
            this.eatWhitespace();
            if (this.eatSeparator()) {
                continue;
            }
            if (!this.eatDirectiveName()) {
                this.eatUntilSeparator();
                continue;
            }
            if (!this.eatSingleWhitespace()) {
                this.eatUntilSeparator();
                continue;
            }
            if (this.eatSeparator())
                continue;
            this.eatDirectiveValue();
            this.eatUntilSeparator();
        }
        this.postprocessTokens();
        Token[] tokensArray = new Token[this.tokens.size()];
        return this.tokens.toArray(tokensArray);
    }

    @Nonnull private void postprocessTokens() {
        ArrayList<Token> newTokens = new ArrayList<>();
        DirectiveNameToken lastDirectiveName = null;
        for (Token t : this.tokens) {
            if (t instanceof DirectiveNameToken) {
                lastDirectiveName = (DirectiveNameToken) t;
            } else if (t instanceof DirectiveValueToken) {
                if (lastDirectiveName == null) throw new RuntimeException("not reached");
                switch (lastDirectiveName.subtype) {
                // source-list
                    case BaseUri:
                    case ChildSrc:
                    case ConnectSrc:
                    case DefaultSrc:
                    case FontSrc:
                    case FormAction:
                    case FrameSrc:
                    case ImgSrc:
                    case ManifestSrc:
                    case MediaSrc:
                    case ObjectSrc:
                    case ScriptSrc:
                    case StyleSrc:
                    case WorkerSrc:
                // media-type-list
                    case PluginTypes:
                // ancestor-source-list
                    case FrameAncestors:
                // sandbox directive value
                    case Sandbox:
                // require-sri-for directive value
                    case RequireSriFor:
                // uri-reference list
                    case ReportUri:
                        newTokens.addAll(splitByWSP(t));
                        continue;
                }
            }
            newTokens.add(t);
        }
        this.tokens = newTokens;
    }

    @Nonnull public static String trimRHSWS(@Nonnull String s) {
        int i;
        for (i = s.length() - 1; i >= 0; --i) {
            int c = s.codePointAt(i);
            if (!WSP.matcher(new String(new int[] {c}, 0, 1)).find())
                break;
        }

        return s.substring(0, i + 1);
    }

    @Nonnull private static List<SubDirectiveValueToken> splitByWSP(@Nonnull Token token) {
        List<SubDirectiveValueToken> tokens = new ArrayList<>();
        @Nullable Location startLocation = token.startLocation;
        Matcher m = NotWSP.matcher(token.value);
        int offset = 0;
        while (m.find(offset)) {
            SubDirectiveValueToken dv = new SubDirectiveValueToken(token.value.substring(m.start(), m.end()));
            if (startLocation != null) {
                dv.startLocation = new Location(startLocation.line, startLocation.column + m.start(),
                    startLocation.offset + m.start());
                dv.endLocation =
                    new Location(startLocation.line, startLocation.column + m.end(), startLocation.offset + m.end());
            }
            offset = m.end();
            tokens.add(dv);
        }
        return tokens;
    }
}
