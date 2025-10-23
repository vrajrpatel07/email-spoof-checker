import React, { useState } from "react";

function App() {
  const [emailText, setEmailText] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const formData = new FormData();
      // send full email content (headers + body)
      formData.append("raw_headers", emailText);

      const response = await fetch(`${process.env.REACT_APP_BACKEND_URL || "http://127.0.0.1:8000/analyze"}`, {
    
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Error analyzing email");
      }

      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: "800px", margin: "40px auto", fontFamily: "Segoe UI, sans-serif" }}>
      <h1 style={{ textAlign: "center", color: "#333" }}>📧 Email Spoof Checker</h1>

      <form onSubmit={handleSubmit} style={{ marginTop: "20px" }}>
        <textarea
          rows="15"
          value={emailText}
          onChange={(e) => setEmailText(e.target.value)}
          placeholder="Paste full email headers and body here..."
          style={{
            width: "100%",
            padding: "10px",
            fontFamily: "monospace",
            fontSize: "14px",
            borderRadius: "6px",
            border: "1px solid #ccc",
          }}
          required
        />

        <button
          type="submit"
          disabled={loading}
          style={{
            marginTop: "15px",
            padding: "10px 20px",
            backgroundColor: "#0078D7",
            color: "white",
            border: "none",
            borderRadius: "5px",
            cursor: "pointer",
            fontSize: "16px",
          }}
        >
          {loading ? "Analyzing..." : "Check Email"}
        </button>
      </form>

      {error && (
        <div style={{ marginTop: "20px", color: "red", fontWeight: "bold" }}>
          ❌ {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: "30px", background: "#f9f9f9", padding: "20px", borderRadius: "6px" }}>
          <h2>🔍 Analysis Result</h2>
          <p><strong>Status:</strong> {result.status}</p>
          <p><strong>SPF:</strong> {result.spf}</p>
          <p><strong>DKIM:</strong> {result.dkim}</p>
          <p><strong>DMARC:</strong> {result.dmarc}</p>
          <p><strong>Malicious:</strong> {result.malicious}</p>

          {result.malicious_findings && result.malicious_findings.length > 0 && (
            <>
              <h3>⚠️ Malicious Findings</h3>
              <ul>
                {result.malicious_findings.map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            </>
          )}

          {result.suspicious_attachments && result.suspicious_attachments.length > 0 && (
            <>
              <h3>📎 Suspicious Attachments</h3>
              <ul>
                {result.suspicious_attachments.map((a, i) => (
                  <li key={i}>{a.filename} — {a.reason}</li>
                ))}
              </ul>
            </>
          )}

          {result.suspicious_urls && result.suspicious_urls.length > 0 && (
            <>
              <h3>🌐 Suspicious URLs</h3>
              <ul>
                {result.suspicious_urls.map((u, i) => (
                  <li key={i}>
                    <a href={u.url} target="_blank" rel="noopener noreferrer">{u.url}</a> — {u.reasons.join(", ")}
                  </li>
                ))}
              </ul>
            </>
          )}

          {/* <p style={{ fontSize: "12px", color: "#666" }}>
            Lines analyzed: {result.num_lines}
          </p> */}
        </div>
      )}
    </div>
  );
}

export default App;
