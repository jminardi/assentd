// Shows the connection state and the key fingerprint, to compare with the phone when pairing.
chrome.runtime.sendMessage({ type: "popup" }, (r) => {
  document.getElementById("status").textContent = r?.status ?? "not running";
  document.getElementById("fp").textContent = r?.fingerprint ?? "";
});
