salvation
==========

This is a general purpose library for working with Content Security Policy policies.

* parse CSP policies into an easy-to-use representation
* ask questions about what a CSP policy allows or restricts
* warn about nonsensical CSP policies and deprecated or nonstandard features
* safely create, manipulate, and merge CSP policies
* render and optimise CSP policies

### Install

```sh
mvn install
```

### Create a Policy

Parse a policy using one of the `Parser.parse` static methods. An `Origin` or `String` may be given as the origin. The third parameter, if given, will be populated with notices.

```java

ArrayList<Notice> notices = new ArrayList<>();
Origin origin = URI.parse("http://example.com");
String policyText = "...";
Policy p = Parser.parse(policyText, origin, notices);
```

To include location information, use `ParserWithLocation.parse` in place of `Parser.parse`.

```java
ArrayList<Notice> notices = new ArrayList<>();
ParserWithLocation.parse("image-src *; script-src none; report-uri /report", "https://example.com", notices);

Notice.getAllErrors(notices).get(0).show(); 
// 1:1: Unrecognised directive-name: "image-src".

Notice.getAllWarnings(notices).get(0).show();
// 1:25: This host name is unusual, and likely meant to be a keyword that is missing the required quotes: 'none'.

Notice.getAllInfos(notices).get(0).show(); 
// 1:31: A draft of the next version of CSP deprecates report-uri in favour of a new report-to directive.
```

A policy may also be created using the `Policy` constructor and populated using the `addDirective` method.

```java
Origin origin = URI.parse("http://example.com");
Policy p = new Policy(origin);
Set<SourceExpression> scriptSourceValues = new HashSet<>();
scriptSourceValues.add(None.INSTANCE;
p.addDirective(new ScriptSrcDirective(scriptSourceValues));
```

### Query a Policy

```java
Policy p = Parser.parse("script-src a; default-src b", "http://example.com");
p.allowsScriptFromSource(URI.parse("http://a")); // true
p.allowsScriptFromSource(URI.parse("http://b")); // false
p.allowsStyleFromSource(URI.parse("http://b")); // true
```
### Manipulate Policies

Intersection merge:

```java
Policy p = Parser.parse("script-src a; default-src b", "http://example.com");
Policy q = Parser.parse("script-src b;", "http://example.com");
p.intersect(q);
p.show(); // script-src; default-src b
```

Union merge:

```java
Policy p = Parser.parse("script-src a; default-src b", "http://example.com");
Policy q = Parser.parse("script-src b;", "http://example.com");
p.union(q);
p.show(); // script-src a b
```