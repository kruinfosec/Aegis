/**
 * Aegis — Smart Contract Vulnerability Scanner
 * main.js: Upload UX, drag-and-drop, loading state
 */

document.addEventListener("DOMContentLoaded", () => {

  /* ── Elements ─────────────────────────────────────────── */
  const themeToggle = document.getElementById("themeToggle");
  const dropZone    = document.getElementById("dropZone");
  const fileInput   = document.getElementById("fileInput");
  const dropContent = document.getElementById("dropContent");
  const fileSelected= document.getElementById("fileSelected");
  const fileNameEl  = document.getElementById("selectedFileName");
  const scanBtn     = document.getElementById("scanBtn");
  const uploadForm  = document.getElementById("uploadForm");
  const btnText     = scanBtn?.querySelector(".btn-text");
  const btnLoading  = scanBtn?.querySelector(".btn-loading");

  /* ── Theme Toggling ───────────────────────────────────── */
  if (themeToggle) {
    // Check local storage or system preference
    const savedTheme = localStorage.getItem("aegis_theme");
    if (savedTheme === "light") {
      document.documentElement.setAttribute("data-theme", "light");
      themeToggle.textContent = "☀️"; // Sun for light mode
    } else {
      themeToggle.textContent = "🌓"; // Moon for dark mode
    }

    themeToggle.addEventListener("click", () => {
      const currentTheme = document.documentElement.getAttribute("data-theme");
      if (currentTheme === "light") {
        document.documentElement.removeAttribute("data-theme");
        localStorage.setItem("aegis_theme", "dark");
        themeToggle.textContent = "🌓";
      } else {
        document.documentElement.setAttribute("data-theme", "light");
        localStorage.setItem("aegis_theme", "light");
        themeToggle.textContent = "☀️";
      }
    });
  }

  if (!dropZone) return; // Not on index page past here, skip

  /* ── File Selected Helper ─────────────────────────────── */
  function handleFile(file) {
    if (!file) return;

    if (!file.name.endsWith(".sol")) {
      showError("Only .sol (Solidity) files are accepted.");
      return;
    }

    if (file.size > 512 * 1024) {
      showError("File is too large. Maximum size is 500 KB.");
      return;
    }

    // Show selected state
    fileNameEl.textContent = file.name;
    dropContent.style.display  = "none";
    fileSelected.style.display = "flex";
    scanBtn.disabled = false;

    // Subtle glow on drop zone
    dropZone.style.borderColor = "var(--cyan)";
    dropZone.style.background  = "var(--cyan-dim)";
  }

  /* ── File Input Change ────────────────────────────────── */
  fileInput.addEventListener("change", () => {
    handleFile(fileInput.files[0]);
  });

  /* ── Drag & Drop ──────────────────────────────────────── */
  ["dragenter", "dragover"].forEach(evt => {
    dropZone.addEventListener(evt, e => {
      e.preventDefault();
      dropZone.classList.add("drag-over");
    });
  });

  ["dragleave", "dragend", "drop"].forEach(evt => {
    dropZone.addEventListener(evt, e => {
      e.preventDefault();
      dropZone.classList.remove("drag-over");
    });
  });

  dropZone.addEventListener("drop", e => {
    e.preventDefault();
    const file = e.dataTransfer?.files[0];
    if (file) {
      // Inject into file input (for form submission)
      const dt = new DataTransfer();
      dt.items.add(file);
      fileInput.files = dt.files;
      handleFile(file);
    }
  });

  /* ── Form Submit — Loading State ──────────────────────── */
  uploadForm.addEventListener("submit", () => {
    if (scanBtn.disabled) return;
    btnText.style.display    = "none";
    btnLoading.style.display = "inline-flex";
    scanBtn.disabled = true;
  });

  /* ── Error Display ────────────────────────────────────── */
  function showError(msg) {
    // Remove old error if any
    const old = document.getElementById("jsError");
    if (old) old.remove();

    const div = document.createElement("div");
    div.id = "jsError";
    div.className = "flash flash-error";
    div.innerHTML = `<span>⚠️</span> ${msg}`;
    uploadForm.prepend(div);

    // Auto-remove after 5s
    setTimeout(() => div.remove(), 5000);
  }

  /* ── Finding Card Stagger Animations ──────────────────── */
  const findingCards = document.querySelectorAll(".finding-card");
  findingCards.forEach((card, i) => {
    card.style.animationDelay = `${i * 0.08}s`;
  });

  /* ── Shield Hover Effect (index) ──────────────────────── */
  const shield = document.getElementById("shieldIcon");
  if (shield) {
    shield.addEventListener("mouseenter", () => {
      shield.style.filter = "drop-shadow(0 0 32px rgba(0,255,231,0.9))";
      shield.style.transform = "scale(1.1) rotate(-5deg)";
      shield.style.transition = "all 0.3s ease";
    });
    shield.addEventListener("mouseleave", () => {
      shield.style.filter = "";
      shield.style.transform = "";
    });
  }

});
