package com.shapesecurity.csp.tokens;


import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class DirectiveNameToken extends Token {
    @Nonnull public final DirectiveNameSubtype subtype;

    public DirectiveNameToken(@Nonnull String value) {
        super(value);
        DirectiveNameSubtype subtype = DirectiveNameSubtype.fromString(value);
        if (subtype == null) {
            throw new IllegalArgumentException("Unrecognised directive name: " + value);
        }
        this.subtype = subtype;
    }

    @Nonnull @Override public String toJSON() {
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
        StyleSrc,

        Referrer, // in draft at http://www.w3.org/TR/2014/WD-referrer-policy-20140807/#referrer-policy-delivery as of 2015-08-27
        UpgradeInsecureRequests, // in draft at http://www.w3.org/TR/2015/WD-upgrade-insecure-requests-20150424/#delivery as of 2015-08-27

        Allow, // never included in an official CSP specification
        Options; // never included in an official CSP specification


        @Nullable static DirectiveNameSubtype fromString(@Nonnull String directiveName) {
            switch (directiveName.toLowerCase()) {
                case "base-uri":
                    return BaseUri;
                case "child-src":
                    return ChildSrc;
                case "connect-src":
                    return ConnectSrc;
                case "default-src":
                    return DefaultSrc;
                case "font-src":
                    return FontSrc;
                case "form-action":
                    return FormAction;
                case "frame-ancestors":
                    return FrameAncestors;
                case "frame-src":
                    return FrameSrc;
                case "img-src":
                    return ImgSrc;
                case "media-src":
                    return MediaSrc;
                case "object-src":
                    return ObjectSrc;
                case "plugin-types":
                    return PluginTypes;
                case "report-uri":
                    return ReportUri;
                case "sandbox":
                    return Sandbox;
                case "script-src":
                    return ScriptSrc;
                case "style-src":
                    return StyleSrc;

                // deprecated or proposed directives
                case "allow":
                    return Allow;
                case "options":
                    return Options;
                case "referrer":
                    return Referrer;
                case "upgrade-insecure-requests":
                    return UpgradeInsecureRequests;
            }
            return null;
        }
    }
}
