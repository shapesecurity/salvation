package com.shapesecurity.salvation.data;

import com.shapesecurity.salvation.Constants;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.regex.Matcher;

public class GUID extends Origin {
    @Nonnull public String value;

    public GUID(@Nonnull String value) {
        this.value = value;
    }

    @Override public boolean equals(Object other) {
        if (!(other instanceof GUID))
            return false;
        return ((GUID) other).value.equalsIgnoreCase(this.value);
    }

    @Nullable public String scheme() {
        Matcher matcher = Constants.schemePattern.matcher(this.value);
        if (matcher.find()) {
            return matcher.group("scheme");
        }
        return null;
    }

    @Override public int hashCode() {
        return this.value.toLowerCase().hashCode();
    }

    @Nonnull @Override public String show() {
        return this.value;
    }
}
