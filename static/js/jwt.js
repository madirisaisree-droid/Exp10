document.addEventListener("DOMContentLoaded", () => {

/* =========================
   Global Variables
========================= */
let accessToken = null;
let refreshTokenValue = null;

const BASE_URL = window.location.origin; // ✅ Dynamic URL


/* =========================
   Helper: Safe Fetch
========================= */
async function safeFetch(url, options) {
  try {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    return { response, data };
  } catch (error) {
    showMessage("Server not reachable. Is Flask running?", "error");
    console.error("Fetch error:", error);
    throw error;
  }
}


/* =========================
   Tab Switching
========================= */
function showTab(tab) {
  document.querySelectorAll(".tab-content")
    .forEach(t => t.classList.remove("active"));

  document.querySelectorAll(".tab-btn")
    .forEach(b => b.classList.remove("active"));

  if (tab === "login") {
    document.getElementById("loginTab")?.classList.add("active");
    document.querySelectorAll(".tab-btn")[0]?.classList.add("active");
  } else {
    document.getElementById("signupTab")?.classList.add("active");
    document.querySelectorAll(".tab-btn")[1]?.classList.add("active");
  }
}


/* =========================
   Message Display
========================= */
function showMessage(text, type) {
  const messageDiv = document.getElementById("message");
  if (!messageDiv) return;

  messageDiv.textContent = text;
  messageDiv.className = `message ${type}`;
  messageDiv.style.display = "block";

  setTimeout(() => {
    messageDiv.style.display = "none";
  }, 4000);
}


/* =========================
   Signup
========================= */
document.getElementById("signupForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("signupEmail")?.value;
  const password = document.getElementById("signupPassword")?.value;
  const confirmPassword = document.getElementById("signupConfirm")?.value;

  if (!email || !password || !confirmPassword) {
    showMessage("All fields required", "error");
    return;
  }

  if (password !== confirmPassword) {
    showMessage("Passwords do not match", "error");
    return;
  }

  if (password.length < 6) {
    showMessage("Password must be at least 6 characters", "error");
    return;
  }

  const { response, data } = await safeFetch(`${BASE_URL}/api/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (response?.ok) {
    showMessage("Registration successful! Please login.", "success");
    document.getElementById("signupForm").reset();
    showTab("login");
  } else {
    showMessage(data?.error || "Signup failed", "error");
  }
});


/* =========================
   Login
========================= */
document.getElementById("loginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const email = document.getElementById("loginEmail")?.value;
  const password = document.getElementById("loginPassword")?.value;

  if (!email || !password) {
    showMessage("Email and password required", "error");
    return;
  }

  const { response, data } = await safeFetch(`${BASE_URL}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (response?.ok) {
    accessToken = data.access_token;
    refreshTokenValue = data.refresh_token;

    document.getElementById("authSection")?.style.setProperty("display", "none");
    document.getElementById("dashboardSection")?.style.setProperty("display", "block");
    document.getElementById("userEmail").textContent = data.user || "";

    if (accessToken) {
      document.getElementById("accessTokenDisplay").textContent =
        accessToken.substring(0, 50) + "...";
    }

    if (refreshTokenValue) {
      document.getElementById("refreshTokenDisplay").textContent =
        refreshTokenValue.substring(0, 50) + "...";
    }

    showMessage("Login successful!", "success");
  } else {
    showMessage(data?.error || "Login failed", "error");
  }
});


/* =========================
   Protected Route
========================= */
async function testProtectedRoute() {
  if (!accessToken) {
    showMessage("Login first", "error");
    return;
  }

  const { response, data } = await safeFetch(`${BASE_URL}/api/protected`, {
    method: "GET",
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const responseArea = document.getElementById("responseArea");
  if (responseArea) {
    responseArea.style.display = "block";
    responseArea.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
  }

  if (response?.ok) {
    showMessage("Access granted!", "success");
  } else {
    showMessage(data?.error || "Access denied", "error");
  }
}


/* =========================
   Refresh Token
========================= */
async function refreshToken() {
  if (!refreshTokenValue) {
    showMessage("No refresh token", "error");
    return;
  }

  const { response, data } = await safeFetch(`${BASE_URL}/api/refresh`, {
    method: "POST",
    headers: { Authorization: `Bearer ${refreshTokenValue}` },
  });

  if (response?.ok && data.access_token) {
    accessToken = data.access_token;
    document.getElementById("accessTokenDisplay").textContent =
      accessToken.substring(0, 50) + "...";

    showMessage("Token refreshed!", "success");
  } else {
    showMessage(data?.error || "Refresh failed", "error");
  }
}


/* =========================
   Logout
========================= */
async function logout() {
  if (!accessToken) return;

  await safeFetch(`${BASE_URL}/api/logout`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  accessToken = null;
  refreshTokenValue = null;

  document.getElementById("authSection")?.style.setProperty("display", "block");
  document.getElementById("dashboardSection")?.style.setProperty("display", "none");
  document.getElementById("loginForm")?.reset();
  document.getElementById("responseArea")?.style.setProperty("display", "none");

  showMessage("Logged out successfully!", "success");
}

});
