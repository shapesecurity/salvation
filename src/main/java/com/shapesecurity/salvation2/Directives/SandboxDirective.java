package com.shapesecurity.salvation2.Directives;

import com.shapesecurity.salvation2.Directive;
import com.shapesecurity.salvation2.Policy;

import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class SandboxDirective extends Directive {
	
	public enum Value
	{
		AllowDownloads("allow-downloads"),
		AllowForms("allow-forms"),
		AllowModals("allow-modals"),
		AllowOrientationLock("allow-orientation-lock"),
		AllowPointerLock("allow-pointer-lock"),
		AllowPopups("allow-popups"),
		AllowPopupsToEscapeSandbox("allow-popups-to-escape-sandbox"),
		AllowPresentation("allow-presentation"),
		AllowSameOrigin("allow-same-origin"),
		AllowScripts("allow-scripts"),
		AllowStorageAccessByUserActivation("allow-storage-access-by-user-activation"),
		AllowTopNavigation("allow-top-navigation"),
		AllowTopNavigationByUserActivation("allow-top-navigation-by-user-activation");
		
		public final String keyword;
		
		Value(String keyword) {
			this.keyword = keyword;
		}
		
		public String getKeyword()
		{
			return keyword;
		}
		
		public static Value fromString(String keyword) {
			for(Value k : Value.values()) {
				if(k.getKeyword().equals(keyword)) {
					return k;
				}
			}
			return null;
		}
	}
	
	private final EnumSet<Value> activeValues = EnumSet.noneOf(Value.class);

	public SandboxDirective(List<String> values, DirectiveErrorConsumer errors) {
		super(values);

		int index = 0;
		for (String token : values) {
			// HTML attribute keywords are ascii-case-insensitive: https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#keywords-and-enumerated-attributes
			String lowcaseToken = token.toLowerCase(Locale.ENGLISH);
			Value value = Value.fromString(lowcaseToken);
			if(value == null) {
				if (token.startsWith("'") || token.startsWith("\"")) {
					errors.add(Policy.Severity.Error, "Unrecognized sandbox keyword " + token + " - note that sandbox keywords do not have \"'\"s", index);
				} else {
					errors.add(Policy.Severity.Error, "Unrecognized sandbox keyword " + token, index);
				}
			} else {
				if(!isActive(value)) {
					activeValues.add(value);
				} else {
					errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword " + value.getKeyword(), index);
				}
			}
			++index;
		}
	}
	
	public boolean allowDownloads() {
		return isActive(Value.AllowDownloads);
	}
	
	public void setAllowDownloads(boolean allowDownloads) {
		setValue(Value.AllowDownloads, allowDownloads);
	}
	
	public boolean allowForms() {
		return isActive(Value.AllowForms);
	}
	
	public void setAllowForms(boolean allowForms) {
		setValue(Value.AllowForms, allowForms);
	}
	
	public boolean allowModals() {
		return isActive(Value.AllowModals);
	}
	
	public void setAllowModals(boolean allowModals) {
		setValue(Value.AllowModals, allowModals);
	}
	public boolean allowOrientationLock() {
		return isActive(Value.AllowOrientationLock);
	}
	
	public void setAllowOrientationLock(boolean allowOrientationLock) {
		setValue(Value.AllowOrientationLock, allowOrientationLock);
	}
	
	public boolean allowPointerLock() {
		return isActive(Value.AllowPointerLock);
	}
	
	public void setAllowPointerLock(boolean allowPointerLock) {
		setValue(Value.AllowPointerLock, allowPointerLock);
	}
	
	public boolean allowPopups() {
		return isActive(Value.AllowPopups);
	}
	
	public void setAllowPopups(boolean allowPopups) {
		setValue(Value.AllowPopups, allowPopups);
	}
	
	public boolean allowPopupsToEscapeSandbox() {
		return isActive(Value.AllowPopupsToEscapeSandbox);
	}
	
	public void setAllowPopupsToEscapeSandbox(boolean allowPopupsToEscapeSandbox) {
		setValue(Value.AllowPopupsToEscapeSandbox, allowPopupsToEscapeSandbox);
	}
	
	public boolean allowPresentation() {
		return isActive(Value.AllowPresentation);
	}
	
	public void setAllowPresentation(boolean allowPresentation) {
		setValue(Value.AllowPresentation, allowPresentation);
	}
	
	public boolean allowSameOrigin() {
		return isActive(Value.AllowSameOrigin);
	}
	
	public void setAllowSameOrigin(boolean allowSameOrigin) {
		setValue(Value.AllowSameOrigin, allowSameOrigin);
	}
	
	public boolean allowScripts() {
		return isActive(Value.AllowScripts);
	}
	
	public void setAllowScripts(boolean allowScripts) {
		setValue(Value.AllowScripts, allowScripts);
	}
	
	public boolean allowStorageAccessByUserActivation() {
		return isActive(Value.AllowStorageAccessByUserActivation);
	}
	
	public void setAllowStorageAccessByUserActivation(boolean allowStorageAccessByUserActivation) {
		setValue(Value.AllowStorageAccessByUserActivation, allowStorageAccessByUserActivation);
	}
	
	public boolean allowTopNavigation() {
		return isActive(Value.AllowTopNavigation);
	}
	
	public void setAllowTopNavigation(boolean allowTopNavigation) {
		setValue(Value.AllowTopNavigation, allowTopNavigation);
	}
	
	public boolean allowTopNavigationByUserActivation() {
		return isActive(Value.AllowTopNavigationByUserActivation);
	}
	
	public void setAllowTopNavigationByUserActivation(boolean allowTopNavigationByUserActivation) {
		setValue(Value.AllowTopNavigationByUserActivation, allowTopNavigationByUserActivation);
	}
	
	public void setValue(Value value, boolean allow) {
		if(isActive(value) == allow) {
			return;
		}
		
		if(allow) {
			this.addValue(value.keyword);
			activeValues.add(value);
		} else {
			this.removeValueIgnoreCase(value.keyword);
			activeValues.remove(value);
		}
	}
	
	public boolean isActive(Value value) {
		return activeValues.contains(value);
	}
	
	public Set<Value> getActiveValues() {
		return EnumSet.copyOf(activeValues);
	}
}
