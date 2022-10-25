package com.shapesecurity.salvation2.Directives;

import com.shapesecurity.salvation2.Directive;
import com.shapesecurity.salvation2.Policy;

import java.util.EnumSet;
import java.util.List;
import java.util.Locale;

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
	
	private final EnumSet<Value> activeKeywords = EnumSet.noneOf(Value.class);

	public SandboxDirective(List<String> values, DirectiveErrorConsumer errors) {
		super(values);

		int index = 0;
		for (String token : values) {
			// HTML attribute keywords are ascii-case-insensitive: https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#keywords-and-enumerated-attributes
			String lowcaseToken = token.toLowerCase(Locale.ENGLISH);
			Value value = Value.fromString(lowcaseToken);
			if(value == null) {
				if (token.startsWith("'")) {
					errors.add(Policy.Severity.Error, "Unrecognized sandbox keyword " + token + " - note that sandbox keywords do not have \"'\"s", index);
				} else {
					errors.add(Policy.Severity.Error, "Unrecognized sandbox keyword " + token, index);
				}
			} else {
				if(!isActive(value)) {
					activeKeywords.add(value);
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
		changeValue(Value.AllowDownloads, allowDownloads);
	}
	
	public boolean allowForms() {
		return isActive(Value.AllowForms);
	}
	
	public void setAllowForms(boolean allowForms) {
		changeValue(Value.AllowForms, allowForms);
	}
	
	public boolean allowModals() {
		return isActive(Value.AllowModals);
	}
	
	public void setAllowModals(boolean allowModals) {
		changeValue(Value.AllowModals, allowModals);
	}
	public boolean allowOrientationLock() {
		return isActive(Value.AllowOrientationLock);
	}
	
	public void setAllowOrientationLock(boolean allowOrientationLock) {
		changeValue(Value.AllowOrientationLock, allowOrientationLock);
	}
	
	public boolean allowPointerLock() {
		return isActive(Value.AllowPointerLock);
	}
	
	public void setAllowPointerLock(boolean allowPointerLock) {
		changeValue(Value.AllowPointerLock, allowPointerLock);
	}
	
	public boolean allowPopups() {
		return isActive(Value.AllowPopups);
	}
	
	public void setAllowPopups(boolean allowPopups) {
		changeValue(Value.AllowPopups, allowPopups);
	}
	
	public boolean allowPopupsToEscapeSandbox() {
		return isActive(Value.AllowPopupsToEscapeSandbox);
	}
	
	public void setAllowPopupsToEscapeSandbox(boolean allowPopupsToEscapeSandbox) {
		changeValue(Value.AllowPopupsToEscapeSandbox, allowPopupsToEscapeSandbox);
	}
	
	public boolean allowPresentation() {
		return isActive(Value.AllowPresentation);
	}
	
	public void setAllowPresentation(boolean allowPresentation) {
		changeValue(Value.AllowPresentation, allowPresentation);
	}
	
	public boolean allowSameOrigin() {
		return isActive(Value.AllowSameOrigin);
	}
	
	public void setAllowSameOrigin(boolean allowSameOrigin) {
		changeValue(Value.AllowSameOrigin, allowSameOrigin);
	}
	
	public boolean allowScripts() {
		return isActive(Value.AllowScripts);
	}
	
	public void setAllowScripts(boolean allowScripts) {
		changeValue(Value.AllowScripts, allowScripts);
	}
	
	public boolean allowStorageAccessByUserActivation() {
		return isActive(Value.AllowStorageAccessByUserActivation);
	}
	
	public void setAllowStorageAccessByUserActivation(boolean allowStorageAccessByUserActivation) {
		changeValue(Value.AllowStorageAccessByUserActivation, allowStorageAccessByUserActivation);
	}
	
	public boolean allowTopNavigation() {
		return isActive(Value.AllowTopNavigation);
	}
	
	public void setAllowTopNavigation(boolean allowTopNavigation) {
		changeValue(Value.AllowTopNavigation, allowTopNavigation);
	}
	
	public boolean allowTopNavigationByUserActivation() {
		return isActive(Value.AllowTopNavigationByUserActivation);
	}
	
	public void setAllowTopNavigationByUserActivation(boolean allowTopNavigationByUserActivation) {
		changeValue(Value.AllowTopNavigationByUserActivation, allowTopNavigationByUserActivation);
	}
	
	private void changeValue(Value value, boolean activate) {
		if(isActive(value) == activate) {
			return;
		}
		
		if(activate) {
			this.addValue(value.keyword);
			activeKeywords.add(value);
		} else {
			this.removeValueIgnoreCase(value.keyword);
			activeKeywords.remove(value);
		}
	}
	
	private boolean isActive(Value value) {
		return activeKeywords.contains(value);
	}
}
