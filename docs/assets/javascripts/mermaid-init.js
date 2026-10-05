// Render mermaid diagrams from the copy of the library this repository serves.
//
// Two problems this solves, both verified in a browser against the live site rather
// than inferred.
//
// First, mkdocs-material lazily fetches mermaid from https://unpkg.com/mermaid@11/ the
// moment it meets a diagram, which puts third-party executable code in a reader's
// browser and pins nothing, since `@11` is a range. The guard in tests/ exists to keep
// the published site from contacting a third party, and it never caught this because
// the URL lives inside the theme bundle it allowlists by digest.
//
// Second, the theme's own rendering has never worked here. On the live site the one
// existing diagram resolves to an empty element with no SVG. Preloading the library
// does not fix that on its own: the theme's pass replaces the source block with an
// empty div before rendering it, so the text is gone by the time mermaid is asked to
// draw. Rendering here, at DOMContentLoaded, gets there first.
//
// The rendered container deliberately does not keep the `mermaid` class, so the theme's
// observer finds nothing left to process and cannot blank the result afterwards.

(function () {
  "use strict";

  // The UMD build renders every `.mermaid` element on DOMContentLoaded by default,
  // which would race the pass below and empty the blocks.
  window.mermaid.startOnLoad = false;

  var RENDERED_CLASS = "acs-mermaid";

  function currentTheme() {
    // Material records the active palette on the html element. A reader on the dark
    // palette gets a dark diagram rather than black text on a dark page.
    var scheme = document.body.getAttribute("data-md-color-scheme") ||
      document.documentElement.getAttribute("data-md-color-scheme") || "";
    return scheme.indexOf("slate") !== -1 ? "dark" : "default";
  }

  function sourceOf(pre) {
    // The source is kept on the element so a palette change can re-render from it.
    // textContent rather than innerHTML, because the fence content is escaped and the
    // parser needs the decoded text.
    if (pre.dataset.acsMermaidSource) return pre.dataset.acsMermaidSource;
    var code = pre.querySelector("code");
    return (code || pre).textContent;
  }

  function renderAll() {
    var blocks = document.querySelectorAll("pre.acs-diagram, div." + RENDERED_CLASS);
    if (!blocks.length) return;

    window.mermaid.initialize({
      startOnLoad: false,
      // Diagram text comes from this repository's own documentation, never from a
      // reader. `strict` is kept anyway so a future page cannot inject markup.
      securityLevel: "strict",
      theme: currentTheme()
    });

    Array.prototype.forEach.call(blocks, function (block, index) {
      var source = sourceOf(block);
      if (!source || !source.trim()) return;

      window.mermaid
        .render("acs-mermaid-" + index + "-" + Date.now(), source)
        .then(function (result) {
          var container = document.createElement("div");
          container.className = RENDERED_CLASS;
          container.dataset.acsMermaidSource = source;
          container.innerHTML = result.svg;
          block.parentNode.replaceChild(container, block);
        })
        .catch(function (error) {
          // A diagram that fails to draw must say so. Silence is how the existing
          // diagram sat broken on the published site without anyone noticing.
          console.error("mermaid failed to render a diagram on this page", error);
        });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", renderAll);
  } else {
    renderAll();
  }

  // Material swaps the palette without reloading, so redraw to match.
  var observer = new MutationObserver(function (records) {
    for (var i = 0; i < records.length; i++) {
      if (records[i].attributeName === "data-md-color-scheme") {
        renderAll();
        return;
      }
    }
  });
  observer.observe(document.body, { attributes: true });
})();
