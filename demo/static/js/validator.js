/*global $*/
/*eslint quotes: [1, "single"]*/
$(function () {
  'use strict';

  function colorize(tokens) {
    return tokens.map(function (token){
      switch (token.type) {
        case 'DirectiveName':
          return '<span class="token directiveName" title="' + tooltipize(token.value) + '">' + token.value + '</span>';
        case 'DirectiveValue':
          return '<span class="token directiveValue' + (token.value[0] === '\'' ? ' keyword' : '') + '">' + token.value + '</span>';
        case 'DirectiveSeparator':
          return '<span class="token directiveSeparator">' + token.value + '</span><br>';
        default:
          return token.value;
      }
    }).join(' ');
  }
  // TODO: add handler for fetchHeader form

  function tooltipize(directive) {
    switch(directive) {
      case 'default-src':
        return 'The default-src directive defines the defaults for most directives you leave unspecified';
      case 'script-src':
        return 'The script-src directive controls a set of script-related privileges for protected page';
      case 'style-src':
        return 'The style-src directive restricts which styles the user may apply to the protected page';
      case 'child-src':
        return 'The child-src directive lists the URLs for Workers and embedded frame contents';
      case 'connect-src':
        return 'The connect-src directive lists the URLs to which protected page can connect using XHR, WebSocket and EventSource';
      case 'font-src':
        return 'The font-src directive restricts from where the protected page can load fonts';
      case 'img-src':
        return 'The img-src directive defines the origins from which images can be loaded';
      case 'media-src':
        return 'The media-src directive restricts the origins allowed to deliver video and audio';
      case 'object-src':
        return 'The object-src directive restricts from where the protected page can load plugins';
      case 'plugin-types':
        return 'The plugin-types controls the protected page\'s ability to load specific types of plugins';
      case 'report-uri':
        return 'The report-uri specifies a URL where a browser will send reports when a content security policy is violated';
      case 'form-action':
        return 'The form-action lists valid endpoints for submission from <form> tags';
      case 'base-uri':
        return 'The base-uri restricts the URLs that can appear in a page\'s <base> element';
      case 'frame-ancestors':
        return 'The frame-ancestors specifies the sources that can embed the current page';
      default:
        console.error('uknown tooltip for ' + directive);
        return '';
    }
  }

  $('form[action="/directHeader"]').on('submit', function (evt) {
    evt.preventDefault();

    var cspType = $('select[name="headerName[]"]').val(),
     cspString = $('input[name="headerValue[]"]').val();

    $.ajax('/directHeader', {
      headers: {
        'Accept': 'application/json'
      },
      data: {
        'headerName[]': cspType,
        'headerValue[]': cspString
      },
      success: function (response) {
        if (response.error){
          $('#output-title').text('Invalid policy');
          $('#output-panel').removeClass('panel-success');
          $('#output-panel').addClass('panel-danger');
          $('#output-body').text(response.message);
        }
        else { //Valid CSP policy
          $('#output-title').text('Valid policy');
          $('#output-panel').removeClass('panel-danger');
          $('#output-panel').addClass('panel-success');
          $('#output-body').html(colorize(response.tokens));
        }

      }
    });
  });

  $('form[action="/fetchHeader"]').on('submit', function(evt) {

    evt.preventDefault();

    var url = $('input[name="url"]').val();
    console.log(url);
    $.ajax('/fetchHeader', {
      headers: {
        'Accept': 'application/json'
      },
      data: {
        'url': url,
      },
      success: function (response) {
        var dest = response.url;
        if(dest) {
          $('input[name="url"]').val(dest);
        }

        if (response.error){
          $('#output-title').text(response.message);
          $('#output-panel').removeClass('panel-success');
          $('#output-panel').addClass('panel-danger');
          $('#output-body').text('');
        }
        else { //Valid CSP policy
          $('#output-title').text('CSP headers found at ' + dest);
          $('#output-panel').removeClass('panel-danger');
          $('#output-panel').addClass('panel-success');
          $('#output-body').html(colorize(response.tokens));
        }
      }
    });
  });
  $('form[action="/fetchHeader"]').submit();
});
