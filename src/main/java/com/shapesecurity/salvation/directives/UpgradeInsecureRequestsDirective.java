package com.shapesecurity.salvation.directives;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.Set;

public class UpgradeInsecureRequestsDirective extends Directive<DirectiveValue> {
    @Nonnull private static final String NAME = "upgrade-insecure-requests";

    public UpgradeInsecureRequestsDirective() {
        super(UpgradeInsecureRequestsDirective.NAME, Collections.EMPTY_SET);
    }

    @Nonnull @Override public Directive<DirectiveValue> construct(Set<DirectiveValue> newValues) {
        return new UpgradeInsecureRequestsDirective();
    }
}
