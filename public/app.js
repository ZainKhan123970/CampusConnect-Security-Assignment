
const result = document.getElementById("result");

document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const data = Object.fromEntries(new FormData(e.target));

  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });

    result.textContent = await response.text();
  } catch (error) {
    result.textContent = "Login request failed. Please try again.";
  }
});

document.getElementById("uploadForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const formData = new FormData(e.target);

  try {
    const response = await fetch("/upload", {
      method: "POST",
      body: formData
    });

    result.textContent = await response.text();
  } catch (error) {
    result.textContent = "Upload request failed. Please try again.";
  }
});

document.getElementById("logout").addEventListener("click", async () => {
  try {
    const response = await fetch("/logout", { method: "POST" });
    result.textContent = await response.text();
  } catch (error) {
    result.textContent = "Logout request failed.";
  }
});
