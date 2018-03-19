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
<<<<<<< HEAD
        NavigateTo,
=======
        NavigateTo, // CSP3; WIP at https://w3c.github.io/webappsec-csp/#directive-navigate-to as of 2018-1-24
>>>>>>> Typo fix
        ObjectSrc,
        PluginTypes,
        PrefetchSrc, // CSP3; in editor's draft at https://w3c.github.io/webappsec-csp/#directive-prefetch-src
        Referrer, // will be removed
        ReportTo, // CSP3; in draft at http://w3c.github.io/webappsec-csp/#directive-report-to
        ReportUri, // CSP3 deprecates it
        RequireSriFor, // defined in https://w3c.github.io/webappsec-subresource-integrity/#opt-in-require-sri-for
        Sandbox,
        ScriptSrc,
        StyleSrc,
        WorkerSrc,

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
                case "navigate-to":
                    return NavigateTo;
                case "object-src":
                    return ObjectSrc;
                case "plugin-types":
                    return PluginTypes;
                case "prefetch-src":
                    return PrefetchSrc;
                case "referrer":
                    return Referrer;
                case "report-to":
                    return ReportTo;
                case "require-sri-for":
                    return RequireSriFor;
                case "sandbox":
                    return Sandbox;
                case "script-src":
                    return ScriptSrc;
                case "style-src":
                    return StyleSrc;
                case "upgrade-insecure-requests":
                    return UpgradeInsecureRequests;
                case "worker-src":
                    return WorkerSrc;

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
