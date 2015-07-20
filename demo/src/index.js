import "core-js";

import * as http from "http";
import * as https from "https";

import * as koa from "koa";
import * as rateLimit from "koa-better-ratelimit";
import * as route from "koa-route";
import * as java from "java";
import * as fs from "fs";
import * as URL from "url";

import fetchHeaderView from "./views/fetch-header";
import requestInputView from "./views/request-input"
import directHeaderView from "./views/direct-header"
import cspReportView from "./views/csp-report"

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

app.use(function *(next){
  yield next;
  this.set("X-XSS-Protection", "1; mode=block");
  this.set("Cache-Control", "no-store, no-cache");
  this.set("X-Frame-Options", "DENY");
  this.set("X-Content-Options", "nosniff");
  this.set("strict-transport-security", "max-age=631138519");
});

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
app.use(route.post("/csp-report", composeAppLogicAndView(cspReport, cspReportView)));

// application logic

function getHeaders(url) {
  let client = url.protocol.startsWith("https:") ? https : http;
  if(client === https) { // TODO remove this. ignoring cert
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }
  return function(next) {
    var options = {
      hostname: url.hostname,
      port: url.port,
      path: url.path,
      agent: false
    };
    let req = client.request(options, res => {
      if (res.statusCode >= 300 && res.statusCode < 400) {
        if (!{}.hasOwnProperty.call(res.headers, "location"))
          return next(new Error(`Received from ${url.href}: ${res.statusCode} HTTP response with no Location header`));
        let locationUrl;
        try {
          locationUrl = URL.parse(URL.resolve(url.href, res.headers.location));
        } catch(e) {
          return next(new Error(`${url.href} redirects to invalid URL`));
        }
        return getHeaders(locationUrl)(next);
      }
      if (res.statusCode < 200 || res.statusCode >= 400)
        return next(new Error(`Received from ${url.href}: ${res.statusCode} ${res.statusMessage}`));
      let headers = [];
      for (let i = 0, l = res.rawHeaders.length; i < l; i += 2) {
        let headerName = res.rawHeaders[i].toLowerCase();
        if (headerName === "content-security-policy" || headerName === "content-security-policy-report-only") {
          headers.push({ kind: headerName, value: res.rawHeaders[i + 1] });
        }
      }
      next(null, {url, headers});
    });
    req.setTimeout(3000);
    req.on('error', function(e) {
      let err = new Error(`unknown error: ${e.code}`);
      switch(e.code) {
        case "ENOTFOUND":
          err = new Error(`error resolving hostname: ${e.hostname}`);
          break;
        case "ECONNRESET":
          err = new Error(`error connecting to ${url.href}`);
          break;
        case "ECONNREFUSED":
          err = new Error(`connection refused by ${url.href}`);
          break;
      }
      return next(err);
    });
    req.end();
  };
}

function* fetchHeader() {
  try {
    // remove querystring, chck for NR IP
    let dest = URL.parse(this.query.url);
    if (!dest.protocol || !dest.hostname) {
      return { error: true, message: `invalid URL: ${this.query.url}`, url: url.href };
    }
    if (isNonRoutableIp(dest.hostname)) {
      return { error: true, message: `non-routable IP address: ${dest.hostname}`, url: url.href };
    }
    let {url, headers} = yield getHeaders(dest);

    if (headers.length < 1) {
      return { error: true, message: `no CSP headers found`, url: url.href };
    } else {
      let policy = Parser.parseSync("", dest.href);
      for (let header of headers) {
        try {
          policy.mergeSync(Parser.parseSync(header.value, dest.href));
        } catch(ex) {
          return { error: true, message: `CSP parsing error: ${ex.cause.getMessageSync()}`, url: url.href};
        }
      }
      let policyText = policy.showSync();
      return {
        message: "policy is valid",
        policyText,
        tokens: Tokeniser.tokeniseSync(policyText).map(x => JSON.parse(x.toJSONSync())),
        url: url.href
      };
    }
  } catch(ex) {
    return { error: true, message: ex.message};
  }
}

function* requestInput() {
  // safari doesn't understand paths in source-expression, frame-ancestors :(
  this.response.set("content-security-policy", "default-src 'none';script-src 'self' code.jquery.com maxcdn.bootstrapcdn.com;img-src 'self';font-src 'self' https://fonts.gstatic.com bootswatch.com;connect-src 'self';style-src 'self' bootswatch.com https://fonts.googleapis.com;frame-ancestors 'none';report-uri /csp-report");
}

function* cspReport() {

}

function* directHeader(){
  let info = { error: true, message: "unknown error" };
  if (!{}.hasOwnProperty.call(this.query, "headerValue[]")) {
    return { error: true, message: "no headerValue[] request parameter given" }
  };
  try {
    let policyArray = [].concat(this.query["headerValue[]"]);
    let policy = Parser.parseSync("", "http://example.com");
    for(let policyText of policyArray) {
      try {
        policy.mergeSync(Parser.parseSync(policyText, "http://example.com"));
      } catch(ex) {
        return { error: true, message: `CSP parsing error: ${ex.cause.getMessageSync()}` };
      }
    }
    let finalPolicyText = policy.showSync();
    info = {
      message: `Policy is valid: ${finalPolicyText}`,
      tokens: Tokeniser.tokeniseSync(finalPolicyText).map(x => JSON.parse(x.toJSONSync())),
    };
  } catch(ex) {
    // node-java error
    if(ex.cause) {
      console.log(ex.cause.getMessageSync());
      info = { error: true, message: `${ex.cause.getMessageSync()}` };
    } else { // other error
      console.log("unexpected error: " + ex.stack);
      info = { error: true, message: "unexpected error" };
    }
  }
  return info;
};

function isNonRoutableIp(hostname) {
  var v4 = /(^0\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^127\.)/;
  var v6 = /^[0:]+:1$/
  return v4.test(hostname) || v6.test(hostname);
}

// go!
var options = {
  key: fs.readFileSync('./key.pem'),
  cert: fs.readFileSync('./cert.pem'),
  ciphers: "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS !RC4",
  honorCipherOrder: true
};
var port = process.env.PORT || 80;
var tls_port = process.env.TLS_PORT || 443;
http.createServer(app.callback()).listen(port);
console.log("server started at port " + port);
https.createServer(options, app.callback()).listen(tls_port);
console.log("TLS server started at port " + tls_port);

