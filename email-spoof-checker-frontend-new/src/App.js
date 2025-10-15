import React, { useState } from "react";
import "./App.css";

function App() {
  const [rawHeaders, setRawHeaders] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    if (!rawHeaders.trim()) {
      alert("Please paste the raw email headers!");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const formData = new URLSearchParams();
      formData.append("raw_headers", rawHeaders);

      const response = await fetch("https://email-spoof-checker.onrender.com/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: formData.toString(),
      });

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setResult({
        status: "Error",
        message: err.message || JSON.stringify(err),
      });
    } finally {
      setLoading(false);
    }
  };

  const statusColor = (status) => {
    switch (status) {
      case "Legit":
        return "#28a745";
      case "Spoof":
        return "#dc3545";
      default:
        return "#ffc107";
    }
  };

  return (
    <div className="App">
      <h1>Email Spoof Checker</h1>
      <textarea
        value={rawHeaders}
        onChange={(e) => setRawHeaders(e.target.value)}
        placeholder="Paste email headers here..."
        rows={12}
      />
      <button onClick={handleAnalyze} disabled={loading}>
        {loading ? "Checking..." : "Check Email"}
      </button>

      {result && (
        <div className="result">
          <h2>Status: <span style={{ color: statusColor(result.status) }}>{result.status}</span></h2>
          <p>SPF: {result.spf}</p>
          <p>DKIM: {result.dkim}</p>
          <p>DMARC: {result.dmarc}</p>
        </div>
      )}
    </div>
  );
}

export default App;
