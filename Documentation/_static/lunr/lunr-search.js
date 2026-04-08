// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0
//
// Cilium Docs – Lunr modal search controller
// Activated by Ctrl/Cmd+K or "/" (outside input fields).
// Lazily loads lunr_index.json + docs.json on first open.
// Delegates heavy work (index parse + search) to lunr-worker.js when Workers
// are available; otherwise falls back to synchronous search in-page.
//
// Version-scoped asset loading:
//   Assets are fetched with a relative URL derived from the <script> tag's own
//   src attribute so they always resolve within the current RTD version prefix
//   (e.g. /en/v1.17/_static/lunr/…).

(function () {
  "use strict";

  // ── Derive the _static/lunr/ base URL from this script's src ────────────
  var _scriptEl =
    document.currentScript ||
    (function () {
      var scripts = document.getElementsByTagName("script");
      return scripts[scripts.length - 1];
    })();

  function _staticBase() {
    if (_scriptEl && _scriptEl.src) {
      // e.g.  /en/v1.17/_static/lunr/lunr-search.js  →  /en/v1.17/_static/lunr/
      return _scriptEl.src.replace(/lunr-search\.js(\?.*)?$/, "");
    }
    // Fallback: relative path (works when served from doc root)
    return "_static/lunr/";
  }

  var BASE = _staticBase();

  // ── State ────────────────────────────────────────────────────────────────
  var _state = {
    open: false,
    loading: false,
    ready: false, // index + docs loaded
    docsStore: null, // Array<{id,url,title,breadcrumb,snippet}>
    selectedIdx: -1,
    worker: null, // Worker | null
    // Callbacks waiting for the worker/index to be ready
    _pendingResolve: null,
  };

  // ── Modal HTML ───────────────────────────────────────────────────────────
  var MODAL_HTML = [
    '<div id="lunr-search-overlay" role="dialog" aria-modal="true" aria-label="Search">',
    '  <div id="lunr-search-modal">',
    '    <div id="lunr-search-input-wrap">',
    '      <svg id="lunr-search-icon" viewBox="0 0 20 20" fill="none" aria-hidden="true">',
    '        <circle cx="8.5" cy="8.5" r="5.75" stroke="currentColor" stroke-width="1.75"/>',
    '        <line x1="13.25" y1="13.25" x2="17.5" y2="17.5" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"/>',
    "      </svg>",
    '      <input id="lunr-search-input" type="search" autocomplete="off" spellcheck="false"',
    '             placeholder="Search docs…" aria-label="Search documentation" />',
    '      <span id="lunr-search-close-hint" aria-label="Close search (Escape)">Esc</span>',
    "    </div>",
    '    <div id="lunr-search-results" role="listbox" aria-label="Search results"></div>',
    '    <div id="lunr-search-status" aria-live="polite"></div>',
    '    <div id="lunr-search-footer" aria-hidden="true">',
    '      <span class="lunr-kbd-hint"><kbd>↑</kbd><kbd>↓</kbd> navigate</span>',
    '      <span class="lunr-kbd-hint"><kbd>↵</kbd> open</span>',
    '      <span class="lunr-kbd-hint"><kbd>Esc</kbd> close</span>',
    "    </div>",
    "  </div>",
    "</div>",
  ].join("\n");

  // ── DOM references (populated after inject) ──────────────────────────────
  var $overlay, $input, $results, $status, $closeHint;

  // ── Inject modal into DOM ────────────────────────────────────────────────
  function _inject() {
    if (document.getElementById("lunr-search-overlay")) return;
    var wrapper = document.createElement("div");
    wrapper.innerHTML = MODAL_HTML;
    document.body.appendChild(wrapper.firstElementChild);

    $overlay = document.getElementById("lunr-search-overlay");
    $input = document.getElementById("lunr-search-input");
    $results = document.getElementById("lunr-search-results");
    $status = document.getElementById("lunr-search-status");
    $closeHint = document.getElementById("lunr-search-close-hint");

    // Close on overlay backdrop click (not modal panel click)
    $overlay.addEventListener("click", function (e) {
      if (e.target === $overlay) _close();
    });

    $closeHint.addEventListener("click", _close);

    $input.addEventListener("input", _onInput);
    $input.addEventListener("keydown", _onInputKeydown);
  }

  // ── Open / Close ─────────────────────────────────────────────────────────
  function _open() {
    if (_state.open) return;
    _inject();
    _state.open = true;
    $overlay.classList.add("lunr-open");

    // Allow display:flex to kick in before starting the transition
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        $overlay.classList.add("lunr-visible");
      });
    });

    $input.focus();
    $input.select();
    document.body.style.overflow = "hidden";

    // Kick off lazy load
    _ensureReady();

    var prev = $input.value.trim();
    if (prev.length > 0) {
      _runQuery(prev);
    } else {
      _setStatus("");
    }
  }

  function _close() {
    if (!_state.open) return;
    _state.open = false;
    $overlay.classList.remove("lunr-visible");

    var overlay = $overlay;
    overlay.addEventListener("transitionend", function handler() {
      overlay.removeEventListener("transitionend", handler);
      overlay.classList.remove("lunr-open");
    });

    document.body.style.overflow = "";
    _state.selectedIdx = -1;
  }

  // ── Lazy loading ─────────────────────────────────────────────────────────
  function _ensureReady() {
    if (_state.ready || _state.loading) return;
    _state.loading = true;
    _setStatus("Loading search index…");

    // Try Web Worker first (avoids UI jank on large indices)
    if (typeof Worker !== "undefined") {
      try {
        var worker = new Worker(BASE + "lunr-worker.js");
        _state.worker = worker;

        worker.addEventListener("message", _onWorkerMessage);
        worker.addEventListener("error", function (e) {
          console.warn(
            "[lunr-search] Worker error, falling back to main thread:",
            e,
          );
          _state.worker = null;
          _loadInline();
        });

        worker.postMessage({ type: "LOAD", base: BASE });
        return;
      } catch (e) {
        console.warn(
          "[lunr-search] Could not create Worker, using main thread:",
          e,
        );
      }
    }

    _loadInline();
  }

  function _loadInline() {
    // Load both resources in parallel
    var p1 = fetch(BASE + "lunr_index.json").then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
    var p2 = fetch(BASE + "docs.json").then(function (r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });

    Promise.all([p1, p2])
      .then(function (results) {
        var rawIndex = results[0];
        var docs = results[1];

        _state.docsStore = _buildDocsMap(docs);

        // Determine if we have a pre-built lunr serialised index or a simple
        // inverted index (fallback produced when Python `lunr` pkg is absent)
        if (rawIndex._format === "simple-inverted") {
          _state._simpleIndex = rawIndex.inverted;
          _state._simpleMode = true;
        } else {
          _state._lunrIndex = lunr.Index.load(rawIndex);
          _state._simpleMode = false;
        }

        _state.ready = true;
        _state.loading = false;
        _setStatus("");

        // Re-run any pending query
        var q = $input ? $input.value.trim() : "";
        if (q.length > 0) _runQuery(q);
      })
      .catch(function (err) {
        console.error("[lunr-search] Failed to load index:", err);
        _state.loading = false;
        _setStatus("Search index unavailable.");
      });
  }

  function _buildDocsMap(docsArray) {
    var map = {};
    for (var i = 0; i < docsArray.length; i++) {
      map[String(docsArray[i].id)] = docsArray[i];
    }
    return map;
  }

  // ── Worker message handler ────────────────────────────────────────────────
  function _onWorkerMessage(e) {
    var msg = e.data;

    if (msg.type === "READY") {
      _state.docsStore = _buildDocsMap(msg.docs);
      _state.ready = true;
      _state.loading = false;
      _setStatus("");
      var q = $input ? $input.value.trim() : "";
      if (q.length > 0) _runQuery(q);
      return;
    }

    if (msg.type === "RESULTS") {
      _renderResults(msg.results, msg.query);
      return;
    }

    if (msg.type === "ERROR") {
      console.error("[lunr-search] Worker reported error:", msg.error);
      _setStatus("Search index unavailable.");
    }
  }

  // ── Query execution ───────────────────────────────────────────────────────
  var _queryDebounce = null;

  function _onInput() {
    clearTimeout(_queryDebounce);
    var q = $input.value.trim();
    if (q.length === 0) {
      $results.innerHTML = "";
      _state.selectedIdx = -1;
      _setStatus("");
      return;
    }
    _queryDebounce = setTimeout(function () {
      _runQuery(q);
    }, 120);
  }

  function _runQuery(query) {
    if (!_state.ready) {
      // Still loading – the load completion handler will re-fire
      return;
    }

    if (_state.worker) {
      _state.worker.postMessage({ type: "SEARCH", query: query });
      return;
    }

    // Inline search
    var hits;
    try {
      hits = _inlineSearch(query);
    } catch (e) {
      console.warn("[lunr-search] Search error:", e);
      hits = [];
    }
    _renderResults(hits, query);
  }

  function _inlineSearch(query) {
    var terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    if (terms.length === 0) return [];

    if (_state._simpleMode) {
      return _simpleSearch(terms);
    }

    // Lunr pre-built index – shape query with term boosts
    var lunrQuery = terms
      .map(function (t) {
        // Title field boost + wildcard for partial match
        return "+title:" + t + "^10 +" + t + "* " + t + "~1";
      })
      .join(" ");

    var raw;
    try {
      raw = _state._lunrIndex.search(lunrQuery);
    } catch (e) {
      // Fall back to simple OR search if query syntax fails
      raw = _state._lunrIndex.search(terms.join(" "));
    }

    return raw
      .slice(0, 20)
      .map(function (r) {
        return _state.docsStore[r.ref];
      })
      .filter(Boolean);
  }

  function _simpleSearch(terms) {
    var inv = _state._simpleIndex;
    var scores = {};

    terms.forEach(function (term) {
      // Exact token match
      if (inv[term]) {
        Object.keys(inv[term]).forEach(function (id) {
          scores[id] = (scores[id] || 0) + 2;
        });
      }
      // Prefix match
      Object.keys(inv).forEach(function (token) {
        if (token !== term && token.indexOf(term) === 0) {
          Object.keys(inv[token]).forEach(function (id) {
            scores[id] = (scores[id] || 0) + 1;
          });
        }
      });
    });

    return Object.keys(scores)
      .sort(function (a, b) {
        return scores[b] - scores[a];
      })
      .slice(0, 20)
      .map(function (id) {
        return _state.docsStore[id];
      })
      .filter(Boolean);
  }

  // ── Result rendering ──────────────────────────────────────────────────────
  function _renderResults(hits, query) {
    $results.innerHTML = "";
    _state.selectedIdx = -1;

    if (!hits || hits.length === 0) {
      _setStatus("No results for <strong>" + _esc(query) + "</strong>.");
      return;
    }

    _setStatus("");
    var terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    var frag = document.createDocumentFragment();

    hits.forEach(function (doc, i) {
      var a = document.createElement("a");
      a.className = "lunr-result-item";
      a.href = _resolveUrl(doc.url);
      a.setAttribute("role", "option");
      a.setAttribute("aria-selected", "false");
      a.setAttribute("data-idx", String(i));
      a.tabIndex = -1;

      var titleEl = document.createElement("div");
      titleEl.className = "lunr-result-title";
      titleEl.innerHTML = _highlight(doc.title || "(untitled)", terms);

      var snippetEl = document.createElement("div");
      snippetEl.className = "lunr-result-snippet";
      snippetEl.innerHTML = _highlight(doc.snippet || "", terms);

      a.appendChild(titleEl);

      if (doc.breadcrumb) {
        var bcEl = document.createElement("div");
        bcEl.className = "lunr-result-breadcrumb";
        bcEl.textContent = doc.breadcrumb;
        a.appendChild(bcEl);
      }

      a.appendChild(snippetEl);

      a.addEventListener("click", function () {
        _close();
      });
      a.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
          _close();
          window.location.href = a.href;
        }
      });

      frag.appendChild(a);
    });

    $results.appendChild(frag);
  }

  // ── URL resolution ─────────────────────────────────────────────────────────
  // doc.url is the relative path within the built docs (e.g. "installation/")
  // We resolve it relative to the version root, which we derive from BASE.
  function _resolveUrl(relUrl) {
    // BASE = e.g. /en/v1.17/_static/lunr/
    // We want /en/v1.17/ + relUrl
    var versionRoot = BASE.replace(/_static\/lunr\/$/, "");
    // Ensure no double slash
    if (!versionRoot.endsWith("/")) versionRoot += "/";
    if (relUrl.startsWith("/")) relUrl = relUrl.slice(1);
    return versionRoot + relUrl;
  }

  // ── Keyboard navigation ───────────────────────────────────────────────────
  function _onInputKeydown(e) {
    if (e.key === "Escape") {
      _close();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      _moveSelection(1);
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      _moveSelection(-1);
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      _activateSelected();
    }
  }

  function _moveSelection(delta) {
    var items = $results.querySelectorAll(".lunr-result-item");
    if (items.length === 0) return;

    // Deselect current
    if (_state.selectedIdx >= 0 && _state.selectedIdx < items.length) {
      items[_state.selectedIdx].classList.remove("lunr-selected");
      items[_state.selectedIdx].setAttribute("aria-selected", "false");
    }

    _state.selectedIdx = Math.max(
      -1,
      Math.min(items.length - 1, _state.selectedIdx + delta),
    );

    if (_state.selectedIdx >= 0) {
      var el = items[_state.selectedIdx];
      el.classList.add("lunr-selected");
      el.setAttribute("aria-selected", "true");
      el.scrollIntoView({ block: "nearest" });
    }
  }

  function _activateSelected() {
    var items = $results.querySelectorAll(".lunr-result-item");
    if (_state.selectedIdx >= 0 && _state.selectedIdx < items.length) {
      _close();
      window.location.href = items[_state.selectedIdx].href;
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function _setStatus(msg) {
    if (!$status) return;
    $status.innerHTML = msg;
    $status.style.display = msg ? "block" : "none";
  }

  function _esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function _highlight(text, terms) {
    if (!terms || terms.length === 0) return _esc(text);
    var escaped = _esc(text);
    terms.forEach(function (term) {
      if (!term) return;
      var re = new RegExp(
        "(" + term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")",
        "gi",
      );
      escaped = escaped.replace(re, '<mark class="lunr-highlight">$1</mark>');
    });
    return escaped;
  }

  // ── Global hotkeys ────────────────────────────────────────────────────────
  document.addEventListener("keydown", function (e) {
    // Ctrl/Cmd+K
    if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
      e.preventDefault();
      if (_state.open) {
        _close();
      } else {
        _open();
      }
      return;
    }

    // "/" key – only when not focused on an input/textarea/select/[contenteditable]
    if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey) {
      var tag = document.activeElement && document.activeElement.tagName;
      var ce =
        document.activeElement && document.activeElement.isContentEditable;
      if (!ce && tag !== "INPUT" && tag !== "TEXTAREA" && tag !== "SELECT") {
        e.preventDefault();
        if (!_state.open) _open();
        return;
      }
    }

    // Esc closes when open
    if (e.key === "Escape" && _state.open) {
      _close();
    }
  });

  // Keep modal closed on back-navigation
  window.addEventListener("popstate", function () {
    if (_state.open) _close();
  });
})();
