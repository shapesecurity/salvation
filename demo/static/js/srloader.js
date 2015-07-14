/*global document*/
/*eslint quotes: [1, "single"]*/
(function() {
	'use strict';

	function unsafeLoadScript(src, errorCallback, successCallback) {
		var s = document.createElement('script');
		s.src = src;
		s.addEventListener('error', errorCallback || function(){});
		s.addEventListener('load', successCallback || function(){});
		document.head.appendChild(s);
	}

	function unsafeLoadStyle(src, errorCallback, successCallback) {
		var s = document.createElement('link');
		s.rel = 'stylesheet';
		s.type = 'text/css';
		s.href = src;
		s.addEventListener('error', errorCallback || function(){});
		s.addEventListener('load', successCallback || function(){});
		document.head.appendChild(s);
	}

	function loadSriScript(opts) {
		var e = document.createElement('script');
		e.src = opts.nonCanonicalSrc;
		e.setAttribute('integrity', opts.hashAlgorithm + '-' + opts.hash);
		e.setAttribute('crossorigin', opts.crossOrigin || 'anonymous');
		e.addEventListener('error', function() {
			if (opts.fallbackSrc) {
				unsafeLoadScript(opts.fallbackSrc, opts.errorCallback, opts.successCallback);
			} else if (opts.errorCallback) {
				opts.errorCallback.apply(this, arguments);
			}
			document.head.removeChild(e);
        });
		e.addEventListener('load', opts.successCallback || function(){});
		document.head.appendChild(e);
	}

	function loadSriStyle(opts) {
		var e = document.createElement('link');
		e.rel = 'stylesheet';
		e.type = 'text/css';
		e.href = opts.nonCanonicalSrc;
		e.setAttribute('integrity', opts.hashAlgorithm + '-' + opts.hash);
		e.setAttribute('crossorigin', opts.crossOrigin || 'anonymous');
		e.addEventListener('error', function() {
			if (opts.fallbackSrc) {
				unsafeLoadStyle(opts.fallbackSrc, opts.errorCallback, opts.successCallback);
			} else if (opts.errorCallback) {
				opts.errorCallback.apply(this, arguments);
			}
			document.head.removeChild(e);
        });
		e.addEventListener('load', opts.successCallback || function(){});
		document.head.appendChild(e);
	}

	// order matters
	loadSriStyle({
		nonCanonicalSrc: '//bootswatch.com/superhero/bootstrap.min.css',
		hashAlgorithm: 'sha256',
		hash: 'o0IkLyCCWGBI+ryg6bL44/f8s4cb7+5bncR4LvU57a8=',
		fallbackSrc: '/css/bootstrap.css',
		successCallback: function () {
			unsafeLoadStyle('/css/css.css');
		}
	});

	loadSriScript({
		nonCanonicalSrc: '//code.jquery.com/jquery-2.1.4.min.js',
		hashAlgorithm: 'sha256',
		hash: '8WqyJLuWKRBVhxXIL1jBDD7SDxU936oZkCnxQbWwJVw=',
		fallbackSrc: '/js/jquery.js',
		successCallback: function() {
			loadSriScript({
				nonCanonicalSrc: '//maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js',
				hashAlgorithm: 'sha256',
				hash: 'Sk3nkD6mLTMOF0EOpNtsIry+s1CsaqQC1rVLTAy+0yc=',
				fallbackSrc: '/js/bootstrap.js',
				successCallback: function() {
					unsafeLoadScript('/js/validator.js');
				}
			});
		}
	});
}());
