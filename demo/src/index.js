import "core-js";

import * as http from "http";
import * as https from "https";

import * as koa from "koa";
import * as rateLimit from "koa-better-ratelimit";
import * as route from "koa-route";
import * as java from "java";

import fetchHeaderView from "./views/fetch-header";
import requestInputView from "./views/request-input"
import directHeaderView from "./views/direct-header"

// initialise
java.classpath.pushDir(__dirname + "/../../target/");

var Parser = java.import("com.shapesecurity.csp.Parser");
var Tokeniser = java.import("com.shapesecurity.csp.Tokeniser");
let app = koa();
app.use(rateLimit({
  duration: 10 * 60 * 1000, // 10 mins
  max: 100,
}));

app.use(require("koa-static")(__dirname + "/../static"));

// routes

function composeAppLogicAndView(appLogic, view) {
  return function*(next) {
    view.call(this, yield* appLogic.call(this));
    yield next;
  };
}

app.use(route.get("/", composeAppLogicAndView(requestInput, requestInputView)));
app.use(route.get("/fetchHeader", composeAppLogicAndView(fetchHeader, fetchHeaderView)));
app.use(route.get("/directHeader", composeAppLogicAndView(directHeader, directHeaderView)));

// application logic

function* fetchHeader() {
  let url = this.query.url;
  let client = url.startsWith("https:") ? https : http;
  let headers = yield next => client.get(this.query.url, res => {
    if (res.statusCode >= 300 && res.statusCode < 400) {
      if (!{}.hasOwnProperty.call(res.headers, "location"))
        return next(new Error(`received ${res.statusCode} HTTP response with no Location header`));
      this.redirect(`/fetchHeader?url=${encodeURIComponent(res.headers.location)}`);
      return next(null, []);
    }
    if (res.statusCode < 200 || res.statusCode >= 400)
      return next(new Error(res.statusMessage));
    let headers = [];
    for (let i = 0, l = res.rawHeaders.length; i < l; i += 2) {
      let headerName = res.rawHeaders[i].toLowerCase();
      if (headerName === "content-security-policy" || headerName === "content-security-policy-report-only") {
        headers.push({ kind: headerName, value: res.rawHeaders[i + 1] });
      }
    }
    next(null, headers);
  })
  if (headers.length < 1) {
    return { error: true, message: "no CSP headers found" };
  } else {
    let policy = Parser.parseSync("", this.query.url);
    for (let header of headers) {
      try {
        policy.mergeSync(Parser.parseSync(header.value, this.query.url));
      } catch(ex) {
        console.log(ex.cause.getMessageSync());
        return { error: true, message: "Error: " + ex.cause.getMessageSync() };
      }
    }
    let policyText = policy.showSync();
    return {
      message: "Policy is valid: " + policyText,
      tokens: Tokeniser.tokeniseSync(policyText).map(x => JSON.parse(x.toJSONSync())),
    };
  }
}

function* requestInput() {
}

function* directHeader(){
  let info = { error: true, message: "unknown error" };
  if (!{}.hasOwnProperty.call(this.query, "headerValue[]")) {
    return { error: true, message: "no headerValue[] request parameter given" }
  };
  try {
    let policyText = this.query["headerValue[]"];
    let policy = Parser.parseSync(policyText, "http://example.com");
    info = {
      message: "Policy is valid: " + policy.showSync(),
      tokens: Tokeniser.tokeniseSync(policyText).map(x => JSON.parse(x.toJSONSync())),
    };
  } catch(ex) {
    console.log(ex.cause.getMessageSync());
    info = { error: true, message: "Error: " + ex.cause.getMessageSync() };
  }
  return info;
};

// go!
var port = 3000;
app.listen(port);
console.log("server started at port " + port);
