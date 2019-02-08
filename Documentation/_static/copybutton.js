function runWhenDOMLoaded(cb) {
  if (document.readyState !== "loading") {
    cb();
  } else if (document.addEventListener) {
    document.addEventListener("DOMContentLoaded", cb);
  } else {
    document.attachEvent("onreadystatechange", function() {
      if (document.readyState == "complete") cb();
    });
  }
}

function codeCellId(index) {
  return "codecell" + index;
}

function clearSelection() {
  if (window.getSelection) {
    window.getSelection().removeAllRanges();
  } else if (document.selection) {
    document.selection.empty();
  }
}

function addCopyButtonToCodeCells() {
  if (window.ClipboardJS === undefined) {
    setTimeout(addCopyButtonToCodeCells, 1000);
    return;
  }
  var codeCells = document.querySelectorAll("pre");
  codeCells.forEach(function(codeCell, index) {
    var wrapper = document.createElement("div");
    wrapper.className = "code-wrapper";
    codeCell.parentNode.insertBefore(wrapper, codeCell);
    wrapper.appendChild(codeCell);
    var id = codeCellId(index);
    codeCell.setAttribute("id", id);
    function clipboardButton(id) {
      var linesCount = codeCell.textContent.trim().split("\n").length;
      var buttonHtml = [];
      buttonHtml.push('<div class="copybutton-wrapper">');
      buttonHtml.push(
        '<img class="copy-icon" src="../_static/copy-icon.png" alt="" />'
      );
      buttonHtml.push(
        '<a class="copybutton" data-clipboard-mode="first-line" data-clipboard-target="#' +
          id +
          '">'
      );
      buttonHtml.push(linesCount > 1 ? "Copy First Line" : "Copy Line");
      buttonHtml.push("</a>");
      if (linesCount > 1) {
        buttonHtml.push(
          '<a class="copybutton" data-clipboard-mode="all"  data-clipboard-target="#' +
            id +
            '">'
        );
        buttonHtml.push("Copy All");
        buttonHtml.push("</a>");
      }
      buttonHtml.push("</div>");
      return buttonHtml.join("\n");
    }
    codeCell.insertAdjacentHTML("afterend", clipboardButton(id));
  });

  new ClipboardJS(".copybutton", {
    text: function(trigger) {
      var parent = trigger.parentNode.parentNode;
      var code = parent.querySelector("pre");
      var mode = trigger.getAttribute("data-clipboard-mode");
      if (mode === "first-line") {
        return code.textContent
          .split("\n")[0]
          .trim()
          .replace(/^\$/, "")
          .trim();
      } else {
        return code.textContent;
      }
    }
  });
}

runWhenDOMLoaded(addCopyButtonToCodeCells);
