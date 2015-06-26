import {html} from "../util";

export default function() {
  this.response.type = "text/html; charset=utf-8";
  this.body = html`<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>CSP Header Inspector and Validator</title>
    <link href="/css/bootstrap.css" type="text/css" rel="stylesheet"/>
    <script src="/js/jquery.js"></script>
    <script src="/js/validator.js"></script>
  </head>
  <body>
    <div class="container">
      <h1 class="page-header">Content Security Policy (CSP) Validator</h1>

      <h2>Validate URL</h2>
      <p>Validate CSP headers as served from the given URL.</p>
      <form action="/fetchHeader" class="well">
        <div class="row">
          <div class="col-md-10">
            <input type="url" name="url" placeholder="https://..." class="form-control"/>
          </div>
          <div class="col-md-2">
            <button class="btn">Go</button>
          </div>
        </div>
      </form>

      <h2>Validate CSP String</h2>
      <p>Validate a raw CSP header/value string.</p>
      <form action="/directHeader" class="well">
        <div class="row">
          <div class="col-md-3">
            <select name="headerName[]" class="form-control">
              <option>Content-Security-Policy:</option>
              <option>Content-Security-Policy-Report-Only:</option>
            </select>
          </div>
          <div class="col-md-7">
            <input type="text" name="headerValue[]" width="120" class="form-control"/>
          </div>
          <div class="col-md-2">
            <button class="btn">Go</button>
          </div>
        </div>
      </form>
      <div class="panel" id="output-panel">
        <div class="panel-heading">
          <div class="panel-title" id="output-title">
          </div>
        </div>
        <div class="panel-body" id="output-body">
        </div>
      </div>
      <hr>
      <p>CSP Validator was built by Sergey Shekyan, Michael Ficarra, Dawson Botsford, Ben Vinegar, and the fine folks at <a href="http://shapesecurity.com">Shape Security</a>.</p>
    </div>
  </body>
</html>`;
}
