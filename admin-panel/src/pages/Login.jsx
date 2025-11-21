import { useState } from "react";

export default function Login() {
  // Pre-fill for convenience while developing
  const [email, setEmail] = useState("admin2@example.com");
  const [password, setPassword] = useState("AdminPass123!");
  const [message, setMessage] = useState("");

  async function handleLogin(e) {
    e.preventDefault();
    setMessage("Logging in...");

    try {
      console.log("➡ Sending login request to http://localhost:4000/api/auth/login");

      const res = await fetch("/api/auth/login", {

        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      let data = null;
      try {
        data = await res.json();
      } catch (parseErr) {
        console.error("❌ Failed to parse JSON from /api/auth/login:", parseErr);
        setMessage(`Server returned non-JSON response (status ${res.status})`);
        return;
      }

      console.log("✅ Login response:", res.status, data);

      if (!res.ok) {
        setMessage(data.error || `Login failed (status ${res.status})`);
        return;
      }

      // store access token for later API calls
      if (data.accessToken) {
        localStorage.setItem("accessToken", data.accessToken);
      }

      if (data.user) {
        localStorage.setItem("currentUser", JSON.stringify(data.user));
      }

      setMessage("Login successful! Redirecting...");

      // redirect to dashboard
      window.location.href = "/dashboard";
    } catch (err) {
      console.error("🚨 Login fetch error:", err);
      setMessage(`Error connecting to server: ${err.message || "Unknown error"}`);
    }
  }

  return (
    <div style={{ maxWidth: "400px", margin: "40px auto", fontFamily: "sans-serif" }}>
      <h2>Admin Login</h2>

      <form
        onSubmit={handleLogin}
        style={{ display: "flex", flexDirection: "column", gap: "10px" }}
      >
        <div>
          <label style={{ display: "block", marginBottom: "4px" }}>Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={{ width: "100%", padding: "6px" }}
          />
        </div>

        <div>
          <label style={{ display: "block", marginBottom: "4px" }}>Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{ width: "100%", padding: "6px" }}
          />
        </div>

        <button type="submit" style={{ padding: "8px 12px", marginTop: "10px" }}>
          Login
        </button>
      </form>

      {message && <p style={{ marginTop: "10px" }}>{message}</p>}
    </div>
  );
}
