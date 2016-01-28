package com.shapesecurity.salvation.tokens;


import javax.annotation.Nonnull;

public class DirectiveNameToken extends Token {
    @Nonnull public final DirectiveNameSubtype subtype;

    public DirectiveNameToken(@Nonnull String value) {
        super(value);
        DirectiveNameSubtype subtype = DirectiveNameSubtype.fromString(value);
        this.subtype = subtype;
    }

    @Nonnull @Override public String toJSON() {
        return super.toJSON("DirectiveName");
    }

    public enum DirectiveNameSubtype {
        BaseUri,
        BlockAllMixedContent, // W3C Candidate Recommendation at http://www.w3.org/TR/mixed-content/#strict-opt-in as of 2015-09-22
        ChildSrc,
        ConnectSrc,
        DefaultSrc,
        FontSrc,
        FormAction,
        FrameAncestors,
        FrameSrc,
        ImgSrc,
        ManifestSrc, // CSP3; in draft at http://w3c.github.io/webappsec-csp/#directive-manifest-src as of 2014-10-26
        MediaSrc,
        ObjectSrc,
        PluginTypes,
        Referrer, // in draft at http://www.w3.org/TR/2014/WD-referrer-policy-20140807/#referrer-policy-delivery as of 2015-08-27
        ReportTo, // CSP3; in draft at http://w3c.github.io/webappsec-csp/#directive-report-to
        ReportUri, // CSP3 deprecates it
        Sandbox,
        ScriptSrc,
        StyleSrc,

        UpgradeInsecureRequests, // W3C Candidate Recommendation at https://www.w3.org/TR/upgrade-insecure-requests/#delivery as of 2015-10-08

        Allow, // never included in an official CSP specification
        Options, // never included in an official CSP specification

        Unrecognised;


        @Nonnull static DirectiveNameSubtype fromString(@Nonnull String directiveName) {
            switch (directiveName.toLowerCase()) {
                case "base-uri":
                    return BaseUri;
                case "block-all-mixed-content":
                    return BlockAllMixedContent;
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
                case "img-src":
                    return ImgSrc;
                case "manifest-src":
                    return ManifestSrc;
                case "media-src":
                    return MediaSrc;
                case "object-src":
                    return ObjectSrc;
                case "plugin-types":
                    return PluginTypes;
                case "referrer":
                    return Referrer;
                case "report-to":
                    return ReportTo;
                case "sandbox":
                    return Sandbox;
                case "script-src":
                    return ScriptSrc;
                case "style-src":
                    return StyleSrc;
                case "upgrade-insecure-requests":
                    return UpgradeInsecureRequests;

                // deprecated directives
                case "allow":
                    return Allow;
                case "frame-src":
                    return FrameSrc;
                case "options":
                    return Options;
                case "report-uri":
                    return ReportUri;
            }
            return Unrecognised;
        }
    }
}
