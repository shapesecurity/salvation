package com.shapesecurity.csp.tokens;


import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class DirectiveNameToken extends Token {
    @Nonnull
    public final DirectiveNameSubtype subtype;

    public DirectiveNameToken(@Nonnull String value) {
        super(value);
        DirectiveNameSubtype subtype = DirectiveNameSubtype.fromString(value);
        if (subtype == null) {
            throw new IllegalArgumentException("Unrecognised directive name: " + value);
        }
        this.subtype = subtype;
    }

    @Nonnull
    @Override
    public String toJSON() {
        return super.toJSON("DirectiveName");
    }

    public enum DirectiveNameSubtype {
        BaseUri,
        ChildSrc,
        ConnectSrc,
        DefaultSrc,
        FontSrc,
        FormAction,
        FrameAncestors,
        FrameSrc,
        ImgSrc,
        MediaSrc,
        ObjectSrc,
        PluginTypes,
        ReportUri,
        Sandbox,
        ScriptSrc,
        StyleSrc;

        @Nullable
        static DirectiveNameSubtype fromString(@Nonnull String directiveName) {
            switch (directiveName.toLowerCase()) {
                case "base-uri": return BaseUri;
                case "child-src": return ChildSrc;
                case "connect-src": return ConnectSrc;
                case "default-src": return DefaultSrc;
                case "font-src": return FontSrc;
                case "form-action": return FormAction;
                case "frame-ancestors": return FrameAncestors;
                case "frame-src": return FrameSrc;
                case "img-src": return ImgSrc;
                case "media-src": return MediaSrc;
                case "object-src": return ObjectSrc;
                case "plugin-types": return PluginTypes;
                case "report-uri": return ReportUri;
                case "sandbox": return Sandbox;
                case "script-src": return ScriptSrc;
                case "style-src": return StyleSrc;
            }
            return null;
        }
    }
}
