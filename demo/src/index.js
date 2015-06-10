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
java.classpath.pushDir(__dirname + '/../../target/');

var Parser = java.import('com.shapesecurity.csp.Parser');
let app = koa();
app.use(rateLimit({
  duration: 10 * 60 * 1000, // 10 mins
  max: 100,
}));

// routes

app.use(route.get("/", requestInput));
app.use(route.get("/fetchHeader", fetchHeader));
app.use(route.get("/directHeader", directHeader));

// application logic

function* fetchHeader(next) {
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
          policyResult = 'Policy is valid: ' + policy.showSync();
        } catch(ex) {
          console.log(ex.cause.getMessageSync());
          policyResult = 'Error: ' + ex.cause.getMessageSync();
        }
      }
    }
    next(null, headers);
  })
  fetchHeaderView.call(this, policyResult);
  yield next;
}

function* requestInput(next) {
  requestInputView.call(this);
  yield next;
}

function* directHeader(next){
  let policyResult;
  try {
    console.log('value is: ' + this.query['headerValue[]']);
    let policy = Parser.parseSync(this.query['headerValue[]']);
    policyResult = 'Policy is valid: ' + policy.showSync();
  } catch(ex) {
    console.log(ex.cause.getMessageSync());
    policyResult = 'Error: ' + ex.cause.getMessageSync();
  }
  directHeaderView.call(this, policyResult);
  yield next;
};

// go!

app.listen(3000);
console.log("server started");
