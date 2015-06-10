import "core-js";

import * as http from "http";
import * as https from "https";

import * as koa from "koa";
import * as route from "koa-route";
import * as java from "java";


// initialise
java.classpath.push(__dirname + '/../../target/csp-parser-0.0.1.jar');

var Parser = java.import('com.shapesecurity.csp.Parser');
let app = koa();

// routes

app.use(route.get("/", requestInput));
app.use(route.get("/fetchHeader", fetchHeader));
app.use(route.get("/directHeader", directHeader));

// helper garbage

function escapeUsing(escaper) {
  return function(literalParts, ...interpolatedParts) {
    let s = literalParts[0];
    for (let [interpolatedPart, literalPart] of zip(interpolatedParts, literalParts.slice(1))) {
      s += escaper(interpolatedPart) + literalPart;
    }
    return s;
  }
}

function* zipWith(combine, ...generators) {
  generators = generators.map(g => g[Symbol.iterator]());
  do {
    let nexts = generators.map(g => g.next());
    if (nexts.some(n => n.done)) break;
    yield combine(...nexts.map(n => n.value));
  } while(true);
}

function* zip(...generators) {
  yield* zipWith(Array.of, ...generators);
}

function hex4(c) {
  let hex = c.charCodeAt(0).toString(16);
  return `${"0000".slice(hex.length)}${hex}`;
}

// TODO: also run appropriate minifiers
let html = escapeUsing(s => s.replace(/[<>&"'`]/g, c => `&#x${hex4(c)};`))
let js = escapeUsing(s => s.replace(/<\/script>/g, c => `\\u${hex4(c[0])}${c.slice(1)}`));

// application logic

function* fetchHeader(next) {
  this.response.type = "text/html; charset=utf-8";
  let policyResult;
  let url = this.query.url;
  let client = url.startsWith("https:") ? https : http;
  let headerPairs = yield next => client.get(this.query.url, res => {
    if (res.statusCode < 200 || res.statusCode >= 400)
      return next(new Error(res.statusMessage));
    let headers = [];
    for (let i = 0, l = res.rawHeaders.length; i < l; i += 2) {
      let headerName = res.rawHeaders[i].toLowerCase();
      if (headerName === "content-security-policy" || headerName === "content-security-policy-report-only") {
        headers.push({ kind: headerName, value: res.rawHeaders[i + 1] });
        try {
          let policy = Parser.parseSync(res.rawHeaders[i + 1]);
          policyResult = policy.show();
        } catch(ex) {
          console.log(ex.cause.getMessageSync());
          policyResult = ex.cause.getMessageSync();
        }
      }
    }
    next(null, headers);
  })
  this.body = html`
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>CSP Header Inspector and Validator</title>
    <style>
    </style>
  </head>
  <body>
  ${JSON.stringify(policyResult)}
  </body>
</html>`;
  yield next;
}

function* requestInput(next) {
  this.response.type = "text/html; charset=utf-8";
  this.body = html`
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>CSP Header Inspector and Validator</title>
    <style>
      body {
        zoom: 200%;
        padding: 2em;
      }
      form p {
        display: flex;
      }
      form input {
        flex: 1;
        min-width: 6em;
      }
      form button {
        width: 3em;
      }
      form button, form select, form input {
        margin: 0 0.2em;
        font-size: 1em;
      }
      .or {
        text-align: center;
        font-size: x-large;
      }
    </style>
  </head>
  <body>
    <form action="/fetchHeader">
      <p>
        <input type="url" name="url" placeholder="https://..." />
        <button>Go</button>
      </p>
    </form>
    <p class="or"> OR </p>
    <form action="/directHeader">
      <p>
        <select name="headerName[]">
          <option>Content-Security-Policy:</option>
          <option>Content-Security-Policy-Report-Only:</option>
        </select>
        <input type="text" name="headerValue[]" width="120" />
        <button>Go</button>
      </p>
    </form>
  </body>
</html>`;
  yield next;
}

function* directHeader(){
  let policyResult;
  try {
    let policy = Parser.parseSync(this.query['headerValue[]']);
    policyResult = policy.show();

  } catch(ex) {
    console.log(ex.cause.getMessageSync());
    policyResult = ex.cause.getMessageSync();
  }
  switch (this.accepts("html", "json", "text")) {
    case "html":
      this.response.type = "text/html; charset=utf-8";
      this.body = html`Hello, ${policyResult}.`;
      return;
    case "json":
      this.body = { message: `Hello, ${policyResult}.` };
      return;
    default:
      this.body = `Hello, ${policyResult}.`;
      return;
  }
};

// go!

app.listen(3000);
