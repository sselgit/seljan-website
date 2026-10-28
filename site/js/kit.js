// Shared helpers for the analyst toolkit pages. Nothing here touches the network or storage.
(function () {
  var SK = window.SK = window.SK || {};

  SK.$ = function (id) { return document.getElementById(id); };

  // Build an element. props: className, text, attrs (object), on (object of handlers).
  SK.el = function (tag, props, kids) {
    var node = document.createElement(tag);
    props = props || {};
    if (props.className) node.className = props.className;
    if (props.text != null) node.textContent = props.text;
    if (props.attrs) Object.keys(props.attrs).forEach(function (k) { node.setAttribute(k, props.attrs[k]); });
    if (props.on) Object.keys(props.on).forEach(function (k) { node.addEventListener(k, props.on[k]); });
    (kids || []).forEach(function (kid) {
      if (kid == null) return;
      node.appendChild(typeof kid === 'string' ? document.createTextNode(kid) : kid);
    });
    return node;
  };

  SK.clear = function (node) { while (node.firstChild) node.removeChild(node.firstChild); };

  var toastTimer = null;
  SK.toast = function (msg) {
    var t = document.getElementById('kit-toast');
    if (!t) {
      t = SK.el('div', { className: 'kit-toast', attrs: { id: 'kit-toast', role: 'status', 'aria-live': 'polite' } });
      document.body.appendChild(t);
    }
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 1800);
  };

  SK.copyText = function (text) {
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      SK.toast(ok ? 'Copied' : 'Copy failed. Select the text and copy it yourself.');
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { SK.toast('Copied'); }, fallback);
    } else {
      fallback();
    }
  };

  SK.download = function (name, text, type) {
    var blob = new Blob([text], { type: type || 'text/plain' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  };

  // Copy button bound to a function that returns the text to copy.
  SK.copyButton = function (label, getText) {
    return SK.el('button', {
      className: 'btn btn-small btn-ghost kit-copy', text: label || 'Copy',
      attrs: { type: 'button' },
      on: { click: function () { SK.copyText(getText()); } }
    });
  };

  // Read a File as an ArrayBuffer (local only).
  SK.readFile = function (file) {
    return new Promise(function (resolve, reject) {
      var r = new FileReader();
      r.onload = function () { resolve(r.result); };
      r.onerror = function () { reject(r.error); };
      r.readAsArrayBuffer(file);
    });
  };

  // Values passed between pages live in the URL fragment (#q=...&k=...&go=1). Browsers never send the
  // fragment to a server, so what a visitor looks up does not appear in anyone's logs.
  SK.hashQuery = function () {
    var out = {}, h = String(location.hash || '').replace(/^#/, '');
    h.split('&').forEach(function (p) {
      var i = p.indexOf('=');
      if (i < 1) return;
      try { out[p.slice(0, i)] = decodeURIComponent(p.slice(i + 1)); } catch (e) { /* ignore a malformed value */ }
    });
    return out;
  };

  SK.pad = function (n, w) { var s = String(n); while (s.length < (w || 2)) s = '0' + s; return s; };
})();
