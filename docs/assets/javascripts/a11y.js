// Accessibility enhancements for the MkDocs Material documentation site:
//   1. Progressive upgrade of the mobile navigation drawer label to a native
//      button with focus, aria-controls, and inert management (keeping the
//      pure-CSS <label for="__drawer"> fallback working when JS is disabled).
//   2. Keyboard activation, focus management, and narrow-viewport `/`, `s`, `f`
//      search shortcuts for the mobile search overlay.
//   3. Arrow-key, Home/End, and Space keyboard navigation for the left nav
//      sidebar and right table-of-contents sidebar.
//   4. Keyboard focusability (tabindex="0" + region label) for overflowing
//      tables and tab strips (leaving pre > code to Material).

(function () {
  "use strict";

  function isEditable(node) {
    if (!node || node.nodeType !== 1) return false;
    var tag = node.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
    return !!node.isContentEditable;
  }

  function upgradeDrawerControl(el) {
    if (el.tagName === "BUTTON") return el;
    var button = document.createElement("button");
    button.type = "button";
    button.className = el.className;
    button.setAttribute("aria-label", el.getAttribute("aria-label") || "Menu");
    button.setAttribute("aria-expanded", "false");
    while (el.firstChild) {
      button.appendChild(el.firstChild);
    }
    if (el.parentNode) {
      el.parentNode.replaceChild(button, el);
    }
    return button;
  }

  function initDrawer() {
    var checkbox = document.getElementById("__drawer");
    var searchCheckbox = document.getElementById("__search");
    var rawControl = document.querySelector(".acs-drawer-toggle");
    var sidebar = document.querySelector(".md-sidebar--primary");
    if (!checkbox || !rawControl || !sidebar) return;

    var button = upgradeDrawerControl(rawControl);
    if (!sidebar.id) sidebar.id = "acs-docs-nav";
    button.setAttribute("aria-controls", sidebar.id);

    var drawerQuery = window.matchMedia("(max-width: 76.234375em)");
    var background = [
      document.querySelector(".md-content"),
      document.querySelector(".md-sidebar--secondary"),
      document.querySelector(".md-footer")
    ].filter(Boolean);
    var wasOpen = false;

    function syncState() {
      var narrow = drawerQuery.matches;
      var open = narrow && checkbox.checked;
      var active = document.activeElement;
      var searchOpen = !!(searchCheckbox && searchCheckbox.checked);
      var shouldRestoreFocus =
        narrow &&
        wasOpen &&
        !open &&
        !searchOpen &&
        (!active || active === document.body || sidebar.contains(active));

      button.setAttribute("aria-expanded", open ? "true" : "false");
      sidebar.inert = narrow && !open;
      for (var i = 0; i < background.length; i++) {
        background[i].inert = open;
      }
      wasOpen = open;

      if (shouldRestoreFocus) {
        button.focus();
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
      }
    });

    syncState();
  }

  function initMobileSearch() {
    var checkbox = document.getElementById("__search");
    var drawerCheckbox = document.getElementById("__drawer");
    var trigger = document.querySelector('header label.md-header__button[for="__search"]');
    var inner = document.querySelector(".md-search__inner");
    var input = document.querySelector(".md-search__input");
    if (!checkbox || !trigger || !inner) return;

    var narrowQuery = window.matchMedia("(max-width: 59.984375em)");
    var wasOpen = false;

    function closeDrawerIfOpen() {
      if (drawerCheckbox && drawerCheckbox.checked) {
        drawerCheckbox.checked = false;
        drawerCheckbox.dispatchEvent(new Event("change", { bubbles: true }));
      }
    }

    function syncSearch() {
      var narrow = narrowQuery.matches;
      var open = checkbox.checked;
      if (open) {
        closeDrawerIfOpen();
      }
      inner.inert = narrow && !open;
      if (narrow && wasOpen && !open) {
        var active = document.activeElement;
        if (!active || active === document.body || inner.contains(active)) {
          trigger.focus();
        }
      }
      wasOpen = open;
    }

    function openSearchFromShortcut() {
      closeDrawerIfOpen();
      inner.inert = false;
      checkbox.checked = true;
      checkbox.dispatchEvent(new Event("change", { bubbles: true }));
      if (input) {
        input.focus();
        window.requestAnimationFrame(function () {
          if (checkbox.checked) input.focus();
        });
      }
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
      closeDrawerIfOpen();
      inner.inert = false;
      window.requestAnimationFrame(function () {
        if (checkbox.checked && input) input.focus();
      });
    }, true);

    // Restore Material's `/`, `s`, and `f` search shortcuts below 60em (e.g. 400%
    // laptop zoom / WCAG 1.4.10 reflow), where `.md-search__inner` is hidden and
    // inert while closed so Material's bare `input.focus()` call would be ignored.
    document.addEventListener("keydown", function (event) {
      if (!narrowQuery.matches || checkbox.checked) return;
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      var key = event.key;
      if (key !== "/" && key !== "s" && key !== "f") return;
      if (isEditable(event.target) || isEditable(document.activeElement)) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      openSearchFromShortcut();
    }, true);

    checkbox.addEventListener("change", syncSearch);
    if (narrowQuery.addEventListener) {
      narrowQuery.addEventListener("change", syncSearch);
    }
    syncSearch();
  }

  function initSidebarKeyboardNav() {
    var SIDEBAR_ITEM_SELECTOR = 'a.md-nav__link[href], label.md-nav__link[tabindex="0"], a.md-source[href]';

    function isCollapsedAncestor(el, root) {
      var cur = el.parentNode;
      while (cur && cur !== root) {
        if (cur.nodeType === 1 && cur.matches && cur.matches("nav.md-nav[data-md-level]")) {
          var parentLi = cur.parentNode;
          if (parentLi && parentLi.nodeType === 1 && parentLi.matches && !parentLi.matches(".md-nav__item--section")) {
            var toggle = parentLi.querySelector("input.md-nav__toggle");
            if (toggle && toggle.parentNode === parentLi && !toggle.checked) {
              return true;
            }
          }
        }
        cur = cur.parentNode;
      }
      return false;
    }

    function isVisibleItem(el, root) {
      if (el.closest && el.closest("[inert]")) return false;
      if (isCollapsedAncestor(el, root)) return false;
      if (typeof window.getComputedStyle === "function") {
        var style = window.getComputedStyle(el);
        if (style.display === "none" || style.visibility !== "visible") return false;
      }
      if (typeof el.getClientRects === "function" && el.getClientRects().length === 0) {
        return false;
      }
      return true;
    }

    function visibleItems(root) {
      var all = root.querySelectorAll(SIDEBAR_ITEM_SELECTOR);
      var list = [];
      for (var i = 0; i < all.length; i++) {
        if (isVisibleItem(all[i], root)) list.push(all[i]);
      }
      return list;
    }

    function focusItem(el) {
      if (!el) return;
      el.focus();
      if (typeof el.scrollIntoView === "function") {
        el.scrollIntoView({ block: "nearest" });
      }
    }

    function groupToggleFor(item) {
      if (item.tagName === "LABEL" && item.getAttribute("for")) {
        return document.getElementById(item.getAttribute("for"));
      }
      var container = item.closest ? item.closest(".md-nav__container") : null;
      if (container) {
        var label = container.querySelector('label.md-nav__link[for]');
        if (label) return document.getElementById(label.getAttribute("for"));
      }
      return null;
    }

    function setGroupOpen(toggle, open) {
      toggle.checked = open;
      var parentLi = toggle.parentNode;
      if (parentLi && parentLi.querySelector) {
        var childNav = parentLi.querySelector("nav.md-nav[data-md-level]");
        if (childNav && childNav.parentNode === parentLi) {
          childNav.setAttribute("aria-expanded", open ? "true" : "false");
        }
      }
      toggle.dispatchEvent(new Event("change", { bubbles: true }));
    }

    function attachSidebar(sidebar, hasGroups) {
      if (!sidebar) return;
      sidebar.addEventListener("keydown", function (event) {
        if (event.metaKey || event.ctrlKey || event.altKey) return;
        var target = event.target && event.target.closest ? event.target.closest(SIDEBAR_ITEM_SELECTOR) : null;
        if (!target || !sidebar.contains(target)) return;

        var key = event.key;
        if (key === "ArrowDown" || key === "ArrowUp" || key === "Home" || key === "End") {
          var items = visibleItems(sidebar);
          var idx = items.indexOf(target);
          if (idx === -1 || items.length === 0) return;
          event.preventDefault();
          if (key === "ArrowDown") {
            focusItem(items[Math.min(idx + 1, items.length - 1)]);
          } else if (key === "ArrowUp") {
            focusItem(items[Math.max(idx - 1, 0)]);
          } else if (key === "Home") {
            focusItem(items[0]);
          } else if (key === "End") {
            focusItem(items[items.length - 1]);
          }
          return;
        }

        if (!hasGroups) return;

        // Material activates <label class="md-nav__link" tabindex="0"> on Enter,
        // but not Space; add Space so group disclosures behave like native buttons.
        if (key === " " && target.tagName === "LABEL" && target.getAttribute("for")) {
          var spaceToggle = document.getElementById(target.getAttribute("for"));
          if (spaceToggle) {
            event.preventDefault();
            setGroupOpen(spaceToggle, !spaceToggle.checked);
          }
          return;
        }

        if (key === "ArrowRight") {
          var rightToggle = groupToggleFor(target);
          if (!rightToggle) return;
          event.preventDefault();
          if (!rightToggle.checked) {
            setGroupOpen(rightToggle, true);
          } else {
            var parentLi = rightToggle.parentNode;
            var childNav = parentLi && parentLi.querySelector ? parentLi.querySelector("nav.md-nav[data-md-level]") : null;
            if (childNav) {
              var childItems = visibleItems(childNav);
              if (childItems.length > 0) focusItem(childItems[0]);
            }
          }
          return;
        }

        if (key === "ArrowLeft") {
          var leftToggle = groupToggleFor(target);
          if (leftToggle && leftToggle.checked) {
            event.preventDefault();
            setGroupOpen(leftToggle, false);
            return;
          }
          // Otherwise move focus up to the enclosing group's toggle control.
          var nav = target.closest ? target.closest("nav.md-nav[data-md-level]") : null;
          var ownerLi = nav ? nav.parentNode : null;
          if (ownerLi && ownerLi.nodeType === 1 && ownerLi.matches && !ownerLi.matches(".md-nav__item--section")) {
            var ownerControl = ownerLi.querySelector('label.md-nav__link[tabindex="0"], a.md-nav__link[href]');
            if (ownerControl && ownerControl !== target) {
              event.preventDefault();
              focusItem(ownerControl);
            }
          }
        }
      });
    }

    attachSidebar(document.querySelector(".md-sidebar--primary"), true);
    attachSidebar(document.querySelector(".md-sidebar--secondary"), false);
  }

  function initScrollableRegions() {
    function labelFor(el) {
      if (el.matches(".md-typeset__scrollwrap")) return "Scrollable table";
      return "Code tabs";
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

    // Material manages tabindex on scrollable pre > code itself; cover tables and tabs here.
    function targets() {
      return document.querySelectorAll(
        ".md-typeset__scrollwrap, .md-typeset .tabbed-labels"
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
    initSidebarKeyboardNav();
    initScrollableRegions();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
