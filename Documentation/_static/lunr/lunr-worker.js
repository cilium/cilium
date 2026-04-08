// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0
//
// Cilium Docs – Lunr search Web Worker
// Loads lunr.min.js + the serialised index + docs store, then responds to
// SEARCH messages so JSON parsing and Lunr queries run off the main thread.
//
// Message protocol (postMessage):
//
//   Main → Worker:
//     { type: "LOAD",   base: "<url prefix ending with />" }
//     { type: "SEARCH", query: "<string>" }
//
//   Worker → Main:
//     { type: "READY",   docs: <Array> }
//     { type: "RESULTS", results: <Array>, query: "<string>" }
//     { type: "ERROR",   error: "<string>" }

"use strict";

var _lunrIndex = null;
var _simpleIndex = null;
var _simpleMode = false;
var _docsStore = []; // flat array, id is array index
var _docsMap = {};
var _simpleTokens = [];
var _base = "";

// ── Load ─────────────────────────────────────────────────────────────────────
function _load(base) {
  _base = base;

  // importScripts is synchronous in Workers – load lunr first
  try {
    importScripts(base + "lunr.min.js");
  } catch (e) {
    self.postMessage({
      type: "ERROR",
      error: "Failed to load lunr.min.js: " + e,
    });
    return;
  }

  // Fetch index and docs in parallel using Promise.all
  Promise.all([
    fetch(base + "lunr_index.json").then(function (r) {
      if (!r.ok) throw new Error("lunr_index.json HTTP " + r.status);
      return r.json();
    }),
    fetch(base + "docs.json").then(function (r) {
      if (!r.ok) throw new Error("docs.json HTTP " + r.status);
      return r.json();
    }),
  ])
    .then(function (data) {
      var rawIndex = data[0];
      var docs = data[1];

      _docsStore = docs;
      _docsMap = {};
      _docsStore.forEach(function (d) {
        _docsMap[String(d.id)] = d;
      });

      if (rawIndex._format === "simple-inverted") {
        _simpleIndex = rawIndex.inverted;
        _simpleTokens = Object.keys(_simpleIndex);
        _simpleMode = true;
      } else {
        _lunrIndex = lunr.Index.load(rawIndex);
        _simpleMode = false;
      }

      self.postMessage({ type: "READY", docs: docs });
    })
    .catch(function (err) {
      self.postMessage({ type: "ERROR", error: String(err) });
    });
}

// ── Search ────────────────────────────────────────────────────────────────────
function _search(query, seq) {
  var terms = _extractTerms(query);
  if (terms.length === 0) {
    self.postMessage({ type: "RESULTS", results: [], query: query, seq: seq });
    return;
  }

  var hits;
  try {
    hits = _simpleMode ? _simpleSearch(terms) : _lunrSearch(terms);
  } catch (e) {
    console.warn("[lunr-worker] search error:", e);
    hits = [];
  }

  self.postMessage({ type: "RESULTS", results: hits, query: query, seq: seq });
}

function _lunrSearch(terms) {
  var raw = _runLunrSearchStrategies(terms);
  return _rerankLunrHits(raw, terms).slice(0, 20);
}

function _runLunrSearchStrategies(terms) {
  var strategies = [_buildStrictLunrQuery(terms), _buildBroadLunrQuery(terms)];
  var merged = [];
  var seen = {};
  var MAX_COLLECTED = 80;

  for (var i = 0; i < strategies.length; i++) {
    var q = strategies[i];
    if (!q) continue;

    var raw = [];
    try {
      raw = _lunrIndex.search(q);
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

function _rerankLunrHits(rawHits, terms) {
  var phrase = terms.length > 1 ? terms.join(" ") : "";

  return rawHits
    .map(function (hit, idx) {
      var doc = _docsMap[String(hit.ref)];
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

function _extractTerms(query) {
  return query
    .toLowerCase()
    .replace(/[^a-z0-9_\-\s]+/g, " ")
    .split(/\s+/)
    .filter(Boolean);
}

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

function _simpleSearch(terms) {
  var inv = _simpleIndex;
  var scores = {};

  terms.forEach(function (term) {
    if (term.length < 2 || _STOP_WORDS[term]) return;

    if (inv[term]) {
      Object.keys(inv[term]).forEach(function (id) {
        scores[id] = (scores[id] || 0) + 4;
      });
    }
    _simpleTokens.forEach(function (token) {
      if (token !== term && token.indexOf(term) === 0) {
        Object.keys(inv[token]).forEach(function (id) {
          scores[id] = (scores[id] || 0) + 2;
        });
      }
    });

    if (term.length >= 4) {
      _simpleTokens.forEach(function (token) {
        if (token.indexOf(term) > 0 || term.indexOf(token) === 0) {
          if (!inv[token]) return;
          Object.keys(inv[token]).forEach(function (id) {
            scores[id] = (scores[id] || 0) + 1;
          });
        }
      });
    }

    if (term.length >= 5) {
      _simpleTokens.forEach(function (token) {
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
      return _docsMap[id];
    })
    .filter(Boolean);
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

// ── Message handler ───────────────────────────────────────────────────────────
self.addEventListener("message", function (e) {
  var msg = e.data;
  if (!msg || !msg.type) return;

  if (msg.type === "LOAD") {
    _load(msg.base);
    return;
  }

  if (msg.type === "SEARCH") {
    _search(msg.query, msg.seq || 0);
    return;
  }
});
