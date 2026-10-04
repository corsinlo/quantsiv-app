// Disclosure rows (A43): a button with aria-controls toggles the panel's `hidden` attribute and
// keeps aria-expanded in sync.
document.addEventListener("click", function (event) {
  const button = event.target.closest("[data-disclosure]");
  if (!button) return;
  const panel = document.getElementById(button.getAttribute("aria-controls"));
  if (!panel) return;
  const open = button.getAttribute("aria-expanded") === "true";
  button.setAttribute("aria-expanded", String(!open));
  panel.hidden = open;
});
