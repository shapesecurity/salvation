/*global $*/
/*eslint quotes: [1, "single"]*/
$(function () {
  'use strict';

  function colorize(tokens) {
    return tokens.map(function (token){
      switch (token.type) {
        case 'DirectiveName':
          return '<span class="token directiveName">' + token.value + '</span>';
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
        console.dir(response);

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
        console.log(response);

        if (response.message === "no CSP headers found"){
          $('#output-title').text('No CSP headers found at specified URL');
          $('#output-panel').removeClass('panel-success');
          $('#output-panel').addClass('panel-danger');
          $('#output-body').text('');
        }
        else { //Valid CSP policy
          $('#output-title').text('CSP headers found at URL');
          $('#output-panel').removeClass('panel-danger');
          $('#output-panel').addClass('panel-success');
          $('#output-body').text(response.message);
        }

      }
    });
  });


});
