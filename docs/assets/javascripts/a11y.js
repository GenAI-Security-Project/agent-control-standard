// Accessibility enhancements for the MkDocs Material documentation site:
//   1. Native keyboard/focus/inert management for the mobile navigation drawer.
//   2. Keyboard activation and focus management for the mobile search trigger.
//   3. Keyboard focusability (tabindex="0" + region label) for overflowing code
//      blocks, wide tables, and tab strips.

(function () {
  "use strict";

  function initDrawer() {
    var checkbox = document.getElementById("__drawer");
    var button = document.querySelector(".acs-drawer-toggle");
    var sidebar = document.querySelector(".md-sidebar--primary");
    if (!checkbox || !button || !sidebar) return;

    var drawerQuery = window.matchMedia("(max-width: 76.234375em)");
    var background = [
      document.querySelector(".md-content"),
      document.querySelector(".md-sidebar--secondary"),
      document.querySelector(".md-footer")
    ].filter(Boolean);

    function syncState() {
      var narrow = drawerQuery.matches;
      var open = narrow && checkbox.checked;
      button.setAttribute("aria-expanded", open ? "true" : "false");
      sidebar.inert = narrow && !open;
      for (var i = 0; i < background.length; i++) {
        background[i].inert = open;
      }
    }

    function firstFocusable(root) {
      return root.querySelector(
        'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), ' +
        'label[tabindex="0"], [tabindex="0"]'
      );
    }

    button.addEventListener("click", function () {
      checkbox.checked = !checkbox.checked;
      checkbox.dispatchEvent(new Event("change", { bubbles: true }));
      if (checkbox.checked && drawerQuery.matches) {
        var target = firstFocusable(sidebar);
        if (target) {
          window.requestAnimationFrame(function () {
            target.focus();
          });
        }
      }
    });

    checkbox.addEventListener("change", syncState);

    if (drawerQuery.addEventListener) {
      drawerQuery.addEventListener("change", function () {
        if (!drawerQuery.matches && checkbox.checked) {
          checkbox.checked = false;
        }
        syncState();
      });
    }

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && drawerQuery.matches && checkbox.checked) {
        checkbox.checked = false;
        checkbox.dispatchEvent(new Event("change", { bubbles: true }));
        button.focus();
      }
    });

    syncState();
  }

  function initMobileSearch() {
    var checkbox = document.getElementById("__search");
    var trigger = document.querySelector('header label.md-header__button[for="__search"]');
    var inner = document.querySelector(".md-search__inner");
    var input = document.querySelector(".md-search__input");
    if (!checkbox || !trigger || !inner) return;

    var narrowQuery = window.matchMedia("(max-width: 59.984375em)");
    var wasOpen = false;

    function syncSearch() {
      var narrow = narrowQuery.matches;
      var open = checkbox.checked;
      inner.inert = narrow && !open;
      if (narrow && wasOpen && !open) {
        var active = document.activeElement;
        if (!active || active === document.body || inner.contains(active)) {
          trigger.focus();
        }
      }
      wasOpen = open;
    }

    // Match native <button> keyboard activation: Enter on keydown, Space on keyup.
    trigger.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        trigger.click();
      } else if (event.key === " ") {
        event.preventDefault();
      }
    });

    trigger.addEventListener("keyup", function (event) {
      if (event.key === " ") {
        event.preventDefault();
        trigger.click();
      }
    });

    // When clicking the trigger while inner is inert, clear inert synchronously so
    // Material's click listener can focus the input immediately.
    trigger.addEventListener("click", function () {
      inner.inert = false;
      window.requestAnimationFrame(function () {
        if (checkbox.checked && input) input.focus();
      });
    }, true);

    checkbox.addEventListener("change", syncSearch);
    if (narrowQuery.addEventListener) {
      narrowQuery.addEventListener("change", syncSearch);
    }
    syncSearch();
  }

  function initScrollableRegions() {
    function labelFor(el) {
      if (el.matches(".md-typeset__scrollwrap")) return "Scrollable table";
      if (el.matches(".tabbed-labels")) return "Code tabs";
      return "Code example";
    }

    function updateElement(el) {
      if (el.closest(".md-search-result__article")) return;
      var overflows = el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1;
      if (overflows) {
        if (!el.hasAttribute("tabindex")) {
          el.setAttribute("tabindex", "0");
          el.dataset.acsScrollable = "true";
        }
        if (!el.hasAttribute("role")) {
          el.setAttribute("role", "region");
          el.dataset.acsRole = "true";
        }
        if (!el.hasAttribute("aria-label") && !el.hasAttribute("aria-labelledby")) {
          el.setAttribute("aria-label", labelFor(el));
          el.dataset.acsLabel = "true";
        }
      } else if (el.dataset.acsScrollable === "true") {
        el.removeAttribute("tabindex");
        delete el.dataset.acsScrollable;
        if (el.dataset.acsRole === "true") {
          el.removeAttribute("role");
          delete el.dataset.acsRole;
        }
        if (el.dataset.acsLabel === "true") {
          el.removeAttribute("aria-label");
          delete el.dataset.acsLabel;
        }
      }
    }

    function targets() {
      return document.querySelectorAll(
        ".md-typeset pre > code, .md-typeset__scrollwrap, .md-typeset .tabbed-labels"
      );
    }

    function updateAll() {
      var list = targets();
      for (var i = 0; i < list.length; i++) {
        updateElement(list[i]);
      }
    }

    updateAll();

    if (typeof ResizeObserver !== "undefined") {
      var ro = new ResizeObserver(function (entries) {
        for (var i = 0; i < entries.length; i++) {
          updateElement(entries[i].target);
        }
      });
      var list = targets();
      for (var i = 0; i < list.length; i++) {
        if (!list[i].closest(".md-search-result__article")) {
          ro.observe(list[i]);
        }
      }
    } else {
      window.addEventListener("resize", updateAll);
    }

    // Re-check when details admonitions or tabs reveal previously hidden blocks.
    document.addEventListener("toggle", function () {
      window.requestAnimationFrame(updateAll);
    }, true);
    document.addEventListener("change", function (event) {
      if (event.target && event.target.closest && event.target.closest(".tabbed-set")) {
        window.requestAnimationFrame(updateAll);
      }
    });
  }

  function init() {
    initDrawer();
    initMobileSearch();
    initScrollableRegions();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
