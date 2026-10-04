/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./app/templates/**/*.html", "./app/static/js/**/*.js", "!./app/static/js/htmx.min.js"],
  theme: { extend: {} },
  plugins: [],
};
