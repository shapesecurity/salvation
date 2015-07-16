import {html} from "../util";

export default function() {
  this.response.type = "text/html; charset=utf-8";
  this.body = html`<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>CSP Header Inspector and Validator</title>
    <script src="/js/srloader.js"></script>
  </head>
  <body>
    <div class="container">
      <h1 class="page-header">Content Security Policy (CSP) Validator</h1>

      <h2>Validate URL</h2>
      <p>Validate CSP headers as served from the given URL.</p>
      <div class="well">
        <div class="row">
          <div class="col-md-12">
            <div class="input-group">
              <label class="sr-only" for="url">Enter URL:</label>
              <input type="url" id="url" name="url" placeholder="https://..." class="form-control" autocomplete="off" value="${this.request.href}"/>
              <span class="input-group-btn">
                <button id="fetchHeader" class="btn btn-default" type="button">Go!</button>
              </span>
            </div>
          </div>
        </div>
      </div>

      <h2>Validate CSP String</h2>
      <p>Validate a raw CSP header/value string.</p>
      <div class="well">
        <div class="row">
          <div class="col-md-12">
            <div id="direct-header-group" class="input-group">
              <span class="input-group-btn">
                <button id="merge" class="btn btn-default" type="button">Merge</button>
              </span>
              <label class="sr-only" for="headerValue">Enter Content Security Policy:</label>
              <input type="text" id="headerValue" name="headerValue" class="form-control" autocomplete="off"/>
              <span class="input-group-btn">
                <button id="directHeader" class="btn btn-default" type="button">Go!</button>
              </span>
            </div>
          </div>
        </div>
      </div>
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
