button.addEventListener("click", () => {
  chrome.tabs.query(
    {
      active: true,
    },
    function (tabs) {
      alert(tabs[0].url);
    }
  );
});