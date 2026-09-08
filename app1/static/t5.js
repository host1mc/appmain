(function () {
  var each = function (list, fn) { Array.prototype.forEach.call(list, fn); };

  each(document.querySelectorAll('.nav'), function (header) {
    var toggle = header.querySelector('.nav-toggle');
    var links = header.querySelector('.links');
    if (!toggle || !links) return;

    var close = function () {
      header.classList.remove('mobile-open');
      toggle.setAttribute('aria-expanded', 'false');
    };

    toggle.addEventListener('click', function () {
      var open = header.classList.toggle('mobile-open');
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });

    each(links.querySelectorAll('a'), function (link) {
      link.addEventListener('click', close);
    });

    document.addEventListener('click', function (event) {
      if (!header.contains(event.target)) close();
    });

    document.addEventListener('keydown', function (event) {
      if (event.key !== 'Escape') return;
      if (header.classList.contains('mobile-open')) toggle.focus();
      close();
    });
  });
})();
