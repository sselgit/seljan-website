// "Paste anything" search on the toolkit hub: detects what was pasted and lists every tool that can handle it.
// Nothing is looked up here; the router only reads the text and builds links.
(function () {
  var SK = window.SK || {}, RT = window.SKRoute;

  function init() {
    var input = document.getElementById('ks-in');
    if (!input || !RT) return;
    var box = document.getElementById('kit-routes'), empty = document.getElementById('ks-empty'), timer = null;

    function run() {
      var value = input.value;
      var shown = RT.render(box, RT.detect(value));
      empty.hidden = !value.trim() || shown > 0;
    }
    input.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(run, 150); });

    var q = SK.hashQuery ? SK.hashQuery() : {};
    if (q.q) { input.value = q.q; run(); }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
