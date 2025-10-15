import React, { useState } from "react";
import "./App.css";

function App() {
  const [rawHeaders, setRawHeaders] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    if (!rawHeaders.trim()) {
      alert("Please paste the raw email headers or body!");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const formData = new URLSearchParams();
      formData.append("raw_headers", rawHeaders);

      const response = await fetch("http://127.0.0.1:8000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formData.toString(),
      });

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setResult({ status: "Error", message: err.message || JSON.stringify(err) });
    } finally {
      setLoading(false);
    }
  };

  const statusColor = (status) => {
    switch (status) {
      case "Legit":
        return "#28a745"; // green
      case "Spoof":
        return "#dc3545"; // red
      case "suspicious":
        return "#ffc107"; // yellow
      case "malicious":
        return "#8b0000"; // dark red
      default:
        return "#6c757d"; // grey
    }
  };

  return (
    <div className="App">
      <header>
        <h1>Email Spoof Checker</h1>
        <p>Paste email headers or body to check SPF/DKIM/DMARC & malicious indicators</p>
      </header>

      <main>
        <textarea
          value={rawHeaders}
          onChange={(e) => setRawHeaders(e.target.value)}
          placeholder="Paste raw email here..."
        />

        <button onClick={handleAnalyze} disabled={loading}>
          {loading ? "Analyzing..." : "Check Email"}
        </button>

        {result && (
          <div className="result-box">
            {result.status === "Error" ? (
              <p className="error-msg">{result.message}</p>
            ) : (
              <>
                <h2>Analysis Result</h2>
                <div className="status-row">
                  <span>Status (Auth): </span>
                  <span style={{ color: statusColor(result.status), fontWeight: "bold" }}>
                    {result.status}
                  </span>
                </div>

                <div className="checks">
                  <p><strong>SPF:</strong> {result.spf}</p>
                  <p><strong>DKIM:</strong> {result.dkim}</p>
                  <p><strong>DMARC:</strong> {result.dmarc}</p>
                </div>

                <div className="malicious">
                  <p><strong>Malicious Verdict:</strong> {result.malicious || "None"}</p>
                  {result.malicious_findings && result.malicious_findings.length > 0 && (
                    <ul>
                      {result.malicious_findings.map((f, i) => <li key={i}>{f}</li>)}
                    </ul>
                  )}
                </div>

                {result.suspicious_urls && result.suspicious_urls.length > 0 && (
                  <div className="suspicious-urls">
                    <h3>Suspicious URLs</h3>
                    <ul>
                      {result.suspicious_urls.map((u, i) => (
                        <li key={i}>{u.url} - {u.reasons.join(", ")}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.suspicious_attachments && result.suspicious_attachments.length > 0 && (
                  <div className="suspicious-files">
                    <h3>Suspicious Attachments</h3>
                    <ul>
                      {result.suspicious_attachments.map((a, i) => (
                        <li key={i}>{a.filename || a.source} {a.reason ? `- ${a.reason}` : ""}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </main>

      <footer>
        <p>&copy; 2025 Email Spoof Checker</p>
      </footer>
    </div>
  );
}

export default App;
