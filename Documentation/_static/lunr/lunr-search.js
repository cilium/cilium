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
    querySeq: 0,
    latestRenderedSeq: 0,
    // Callbacks waiting for the worker/index to be ready
    _pendingResolve: null,
  };

  var _STOP_WORDS = {
    a: 1,
    an: 1,
    the: 1,
    and: 1,
    or: 1,
    but: 1,
    in: 1,
    on: 1,
    at: 1,
    to: 1,
    for: 1,
    of: 1,
    with: 1,
    by: 1,
    from: 1,
    is: 1,
    are: 1,
    was: 1,
    were: 1,
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
  var _prewarmDone = false;
  var _scrollLock = {
    locked: false,
    y: 0,
    htmlOverflow: "",
    bodyOverflow: "",
    bodyPosition: "",
    bodyTop: "",
    bodyLeft: "",
    bodyRight: "",
    bodyWidth: "",
  };

  function _lockBackgroundScroll(lock) {
    if (lock) {
      if (_scrollLock.locked) return;
      _scrollLock.locked = true;
      _scrollLock.y = window.scrollY || document.documentElement.scrollTop || 0;

      _scrollLock.htmlOverflow = document.documentElement.style.overflow;
      _scrollLock.bodyOverflow = document.body.style.overflow;
      _scrollLock.bodyPosition = document.body.style.position;
      _scrollLock.bodyTop = document.body.style.top;
      _scrollLock.bodyLeft = document.body.style.left;
      _scrollLock.bodyRight = document.body.style.right;
      _scrollLock.bodyWidth = document.body.style.width;

      document.documentElement.style.overflow = "hidden";
      document.body.style.overflow = "hidden";
      document.body.style.position = "fixed";
      document.body.style.top = -_scrollLock.y + "px";
      document.body.style.left = "0";
      document.body.style.right = "0";
      document.body.style.width = "100%";
      return;
    }

    if (!_scrollLock.locked) return;
    _scrollLock.locked = false;

    document.documentElement.style.overflow = _scrollLock.htmlOverflow;
    document.body.style.overflow = _scrollLock.bodyOverflow;
    document.body.style.position = _scrollLock.bodyPosition;
    document.body.style.top = _scrollLock.bodyTop;
    document.body.style.left = _scrollLock.bodyLeft;
    document.body.style.right = _scrollLock.bodyRight;
    document.body.style.width = _scrollLock.bodyWidth;
    window.scrollTo(0, _scrollLock.y);
  }

  // ── Inject modal into DOM ────────────────────────────────────────────────
  function _inject() {
    if (!document.body) return false;
    if (document.getElementById("lunr-search-overlay")) {
      $overlay = document.getElementById("lunr-search-overlay");
      $input = document.getElementById("lunr-search-input");
      $results = document.getElementById("lunr-search-results");
      $status = document.getElementById("lunr-search-status");
      $closeHint = document.getElementById("lunr-search-close-hint");
      return Boolean($overlay && $input && $results && $status && $closeHint);
    }

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

    return true;
  }

  // ── Open / Close ─────────────────────────────────────────────────────────
  function _open() {
    if (_state.open) return;
    if (!_inject()) return;
    _state.open = true;
    $overlay.classList.add("lunr-open");

    // Allow display:flex to kick in before starting the transition
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        $overlay.classList.add("lunr-visible");
        // Lock scroll after the first visible frame to avoid blocking open paint.
        _lockBackgroundScroll(true);
      });
    });

    $input.focus();
    $input.select();

    // Kick off load in the next task to keep open animation snappy.
    setTimeout(_ensureReady, 0);

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

    _lockBackgroundScroll(false);
    _state.selectedIdx = -1;
  }

  function _prewarmSearch() {
    if (_prewarmDone || _state.ready || _state.loading) return;
    if (!_inject()) return;
    _prewarmDone = true;
    _ensureReady();
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
          _state._simpleTokens = Object.keys(rawIndex.inverted || {});
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
      _renderResults(msg.results, msg.query, msg.seq || 0);
      return;
    }

    if (msg.type === "ERROR") {
      console.error("[lunr-search] Worker reported error:", msg.error);
      _setStatus("Search index unavailable.");
    }
  }

  // ── Query execution ───────────────────────────────────────────────────────
  var _queryDebounce = null;
  var _DEBOUNCE_MS = 80;
  var _MIN_QUERY_LEN = 2;

  function _onInput() {
    clearTimeout(_queryDebounce);
    var q = $input.value.trim();
    if (q.length === 0) {
      $results.innerHTML = "";
      _state.selectedIdx = -1;
      _setStatus("");
      return;
    }

    if (q.length < _MIN_QUERY_LEN) {
      $results.innerHTML = "";
      _state.selectedIdx = -1;
      _setStatus("Type at least " + _MIN_QUERY_LEN + " characters.");
      return;
    }

    _queryDebounce = setTimeout(function () {
      _runQuery(q);
    }, _DEBOUNCE_MS);
  }

  function _runQuery(query) {
    if (!_state.ready) {
      // Still loading – the load completion handler will re-fire
      return;
    }

    if (query.length < _MIN_QUERY_LEN) {
      return;
    }

    _state.querySeq += 1;
    var seq = _state.querySeq;

    if (_state.worker) {
      _state.worker.postMessage({ type: "SEARCH", query: query, seq: seq });
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
    _renderResults(hits, query, seq);
  }

  function _inlineSearch(query) {
    var terms = _extractTerms(query);
    if (terms.length === 0) return [];

    if (_state._simpleMode) {
      return _simpleSearch(terms);
    }

    var raw = _runLunrSearchStrategies(_state._lunrIndex, terms);
    return _rerankLunrHits(raw, terms, _state.docsStore).slice(0, 20);
  }

  function _simpleSearch(terms) {
    var inv = _state._simpleIndex;
    var tokens = _state._simpleTokens || Object.keys(inv);
    var scores = {};

    terms.forEach(function (term) {
      if (term.length < 2 || _STOP_WORDS[term]) return;

      // Exact token match
      if (inv[term]) {
        Object.keys(inv[term]).forEach(function (id) {
          scores[id] = (scores[id] || 0) + 4;
        });
      }

      // Prefix match
      tokens.forEach(function (token) {
        if (token !== term && token.indexOf(term) === 0) {
          Object.keys(inv[token]).forEach(function (id) {
            scores[id] = (scores[id] || 0) + 2;
          });
        }
      });

      // Infix match: helps with derivatives like "contributing" vs "contribute"
      if (term.length >= 4) {
        tokens.forEach(function (token) {
          if (token.indexOf(term) > 0 || term.indexOf(token) === 0) {
            if (!inv[token]) return;
            Object.keys(inv[token]).forEach(function (id) {
              scores[id] = (scores[id] || 0) + 1;
            });
          }
        });
      }

      // Tiny fuzzy window for typo tolerance while staying cheap.
      if (term.length >= 5) {
        tokens.forEach(function (token) {
          if (Math.abs(token.length - term.length) > 1) return;
          if (token.charAt(0) !== term.charAt(0)) return;
          if (!_withinOneEdit(term, token)) return;
          if (!inv[token]) return;
          Object.keys(inv[token]).forEach(function (id) {
            scores[id] = (scores[id] || 0) + 1;
          });
        });
      }
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

  function _extractTerms(query) {
    return query
      .toLowerCase()
      .replace(/[^a-z0-9_\-\s]+/g, " ")
      .split(/\s+/)
      .filter(Boolean);
  }

  function _runLunrSearchStrategies(index, terms) {
    var strategies = [
      _buildStrictLunrQuery(terms),
      _buildBroadLunrQuery(terms),
    ];
    var merged = [];
    var seen = {};
    var MAX_COLLECTED = 80;

    for (var i = 0; i < strategies.length; i++) {
      var q = strategies[i];
      if (!q) continue;

      var raw = [];
      try {
        raw = index.search(q);
      } catch (e) {
        continue;
      }

      for (var j = 0; j < raw.length; j++) {
        var ref = String(raw[j].ref);
        if (seen[ref]) continue;
        seen[ref] = true;
        merged.push(raw[j]);
      }

      if (merged.length >= MAX_COLLECTED) break;
    }

    return merged;
  }

  function _rerankLunrHits(rawHits, terms, docsMap) {
    var phrase = terms.length > 1 ? terms.join(" ") : "";

    return rawHits
      .map(function (hit, idx) {
        var doc = docsMap[String(hit.ref)];
        if (!doc) return null;

        var title = (doc.title || "").toLowerCase();
        var breadcrumb = (doc.breadcrumb || "").toLowerCase();
        var snippet = (doc.snippet || "").toLowerCase();

        var score = (hit.score || 0) * 100;
        score += Math.max(0, 40 - idx);

        if (phrase) {
          if (title.indexOf(phrase) !== -1) score += 300;
          if (breadcrumb.indexOf(phrase) !== -1) score += 120;
          if (snippet.indexOf(phrase) !== -1) score += 80;
        }

        terms.forEach(function (term) {
          if (_containsWholeWord(title, term)) {
            score += 30;
          } else if (title.indexOf(term) !== -1) {
            score += 15;
          }

          if (_containsWholeWord(breadcrumb, term)) {
            score += 10;
          }

          if (snippet.indexOf(term) !== -1) {
            score += 5;
          }
        });

        return { doc: doc, score: score, idx: idx };
      })
      .filter(Boolean)
      .sort(function (a, b) {
        if (b.score !== a.score) return b.score - a.score;
        return a.idx - b.idx;
      })
      .map(function (item) {
        return item.doc;
      });
  }

  function _containsWholeWord(text, term) {
    if (!text || !term) return false;
    var safe = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp("\\b" + safe + "\\b", "i").test(text);
  }

  function _buildStrictLunrQuery(terms) {
    return terms
      .map(function (t) {
        var clauses = [
          "title:" + t + "^12",
          "title:" + t + "*^8",
          t + "^5",
          t + "*^3",
        ];
        if (t.length >= 5) clauses.push(t + "~1^2");
        return clauses.join(" ");
      })
      .join(" ");
  }

  function _buildBroadLunrQuery(terms) {
    return terms
      .map(function (t) {
        if (t.length >= 5) return t + "* " + t + "~1";
        return t + "*";
      })
      .join(" ");
  }

  function _withinOneEdit(a, b) {
    if (a === b) return true;
    var la = a.length;
    var lb = b.length;
    if (Math.abs(la - lb) > 1) return false;

    var i = 0;
    var j = 0;
    var edits = 0;

    while (i < la && j < lb) {
      if (a.charAt(i) === b.charAt(j)) {
        i += 1;
        j += 1;
        continue;
      }

      edits += 1;
      if (edits > 1) return false;

      if (la > lb) {
        i += 1;
      } else if (lb > la) {
        j += 1;
      } else {
        i += 1;
        j += 1;
      }
    }

    if (i < la || j < lb) edits += 1;
    return edits <= 1;
  }

  // ── Result rendering ──────────────────────────────────────────────────────
  function _renderResults(hits, query, seq) {
    if (seq && seq < _state.latestRenderedSeq) {
      return;
    }
    if (seq) {
      _state.latestRenderedSeq = seq;
    }

    $results.innerHTML = "";
    _state.selectedIdx = -1;

    if (!hits || hits.length === 0) {
      _setStatus("No results for <strong>" + _esc(query) + "</strong>.");
      return;
    }

    _setStatus("");
    var terms = _extractTerms(query);
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

  function _bindSearchTrigger() {
    document.addEventListener("click", function (e) {
      if (!e.target || !e.target.closest) return;
      var trigger = e.target.closest("#lunr-search-trigger");
      if (!trigger) return;
      e.preventDefault();
      _open();
    });

    // Start loading before click to make opening feel immediate.
    document.addEventListener("mousedown", function (e) {
      if (!e.target || !e.target.closest) return;
      if (e.target.closest("#lunr-search-trigger")) {
        _prewarmSearch();
      }
    });

    document.addEventListener(
      "touchstart",
      function (e) {
        if (!e.target || !e.target.closest) return;
        if (e.target.closest("#lunr-search-trigger")) {
          _prewarmSearch();
        }
      },
      { passive: true },
    );

    document.addEventListener("focusin", function (e) {
      if (!e.target || !e.target.closest) return;
      if (e.target.closest("#lunr-search-trigger")) {
        _prewarmSearch();
      }
    });
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

  // Start loading the search index during browser idle time so it is ready
  // before the user ever touches the search trigger.
  function _idleWarm() {
    if (typeof requestIdleCallback !== "undefined") {
      requestIdleCallback(
        function () {
          _ensureReady();
        },
        { timeout: 2000 },
      );
    } else {
      // Safari / older browsers: small delay keeps page-load paint unblocked.
      setTimeout(_ensureReady, 200);
    }
  }

  // Pre-create the modal DOM so opening does not incur first-use DOM cost,
  // then immediately queue the idle warm-up.
  if (document.readyState === "loading") {
    document.addEventListener(
      "DOMContentLoaded",
      function () {
        _inject();
        _idleWarm();
      },
      { once: true },
    );
  } else {
    _inject();
    _idleWarm();
  }
  _bindSearchTrigger();
})();
