/*global $ document console*/
/*eslint quotes: [1, "single"]*/
$(function () {
  'use strict';

  function colorize(tokens) {
    return tokens.map(function (token){
      switch (token.type) {
        case 'DirectiveName':
          return '<span class="token directiveName" title="' + tooltipize(token.value) + ' ">' + token.value + '</span>';
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
        console.info('unknown tooltip for ' + directive);
        return 'Directive is either deprecated or not invented yet';
    }
  }

  function displayResults(response) {
    var dest = response.url;
    if(dest) {
      $('input[name="url"]').val(dest);
    }

    var outputBody = $('#output-body');
    outputBody.empty();

    if (response.error){
      $('#output-panel').removeClass('panel-success');
      $('#output-panel').addClass('panel-danger');
      if(response.originalPolicy) {
        $('#output-title').text('Invalid policy' + (dest ? ' at ' + dest : ''));
        outputBody
          .append($('<p>').text(response.message))
          .append($('<pre>').html(response.originalPolicy));
      } else {
        $('#output-title').text(dest ? 'Error fetching CSP headers from ' + dest : 'Error');
        outputBody.text(response.message);
      }
    } else {
      $('#output-title').text('Valid policy' + (dest ? ' at ' + dest : ''));
      $('#output-panel').removeClass('panel-danger');
      $('#output-panel').addClass('panel-success');
      if(response.warnings && response.warnings.length > 0) {
        outputBody.append(response.warnings.map(function(warningText) {
          return $('<div class="alert alert-warning">')
            .append($('<h4>').text('Warning!'))
            .append($('<p>').text(warningText));
        }));
      }
      outputBody.append($('<p>').html(colorize(response.tokens)));
    }
  }

  function handleError(jqXhr, errorType, error) {
    $('#output-panel').removeClass('panel-success');
    $('#output-panel').addClass('panel-danger');
    switch (errorType) {
      case 'timeout':
        $('#output-title').text('Request timed out');
        break;
      case 'abort':
        $('#output-title').text('Request aborted');
        break;
      default:
        $('#output-title').text('Error');
    }
    $('#output-body').empty().text(error.message);
  }

  $('#fetchHeader').on('submit', function(evt) {
    evt.preventDefault();
    $('.btn.btn-info').prop('disabled', true);
    var url = $('input[name="url"]').val();
    $.ajax('/fetchHeader', {
      timeout: 15e3,
      headers: {
        'Accept': 'application/json'
      },
      data: {
        'url': url
      }
    })
    .done(displayResults)
    .error(handleError)
    .always(function() {
      $('.btn.btn-info').prop('disabled', false);
    });
  });

  $('#directHeader').on('submit', function (evt) {
    evt.preventDefault();
    $('.btn.btn-info').prop('disabled', true);
    var cspElements = [].slice.call(document.querySelectorAll('input[name="headerValue[]"]'));
    var cspArray = $.param({'headerValue[]': cspElements.map(function(el) { return el.value; })});

    $.ajax('/directHeader', {
      timeout: 5e3,
      headers: {
        'Accept': 'application/json'
      },
      processData: false,
      data: cspArray
    })
    .done(displayResults)
    .error(handleError)
    .always(function() {
      $('.btn.btn-info').prop('disabled', false);
    });
  });

  $('#directHeader').delegate('.btn-add', 'click', function(evt) {
    evt.preventDefault();
    var row = $('#directHeaderInputTemplate').clone();
    row.find('.btn-go').parent().remove();
    row.find('.btn-add').removeClass('btn-add').addClass('btn-remove').removeClass('btn-success').addClass('btn-danger');
    row.find('.glyphicon-plus').removeClass('glyphicon-plus').addClass('glyphicon-minus');
    row.find('input').val('');
    row.find('input').attr('placeholder', 'Enter CSP to merge');
    row.find('input').removeAttr('id');
    row.appendTo($('#directHeader'));
    return false;
  });

  $('#directHeader').delegate('.btn-remove', 'click', function(evt) {
    $(this).parents('.row').remove();
    evt.preventDefault();
    return false;
  });

  $('#fetchHeader').submit();
});
