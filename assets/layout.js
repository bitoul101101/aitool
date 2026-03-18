setTimeout(() => {
  document.querySelectorAll(".toast").forEach((el) => el.remove());
}, 5000);

(() => {
  const url = new URL(window.location.href);
  if (url.searchParams.has("notice") || url.searchParams.has("error")) {
    url.searchParams.delete("notice");
    url.searchParams.delete("error");
    history.replaceState(null, "", url.pathname + (url.search ? url.search : ""));
  }
})();
