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
  var terms = query.toLowerCase().split(/\s+/).filter(Boolean);
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
  var lunrQuery = terms
    .map(function (t) {
      return "+title:" + t + "^8 +" + t + "*";
    })
    .join(" ");

  var raw;
  try {
    raw = _lunrIndex.search(lunrQuery);
  } catch (e) {
    raw = _lunrIndex.search(terms.join(" "));
  }

  return raw
    .slice(0, 20)
    .map(function (r) {
      return _docsMap[r.ref];
    })
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
        scores[id] = (scores[id] || 0) + 2;
      });
    }
    _simpleTokens.forEach(function (token) {
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
      return _docsMap[id];
    })
    .filter(Boolean);
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
