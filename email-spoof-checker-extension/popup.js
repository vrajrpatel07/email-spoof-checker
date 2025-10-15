document.getElementById("checkBtn").addEventListener("click", async () => {
  const headers = document.getElementById("headers").value.trim();
  const resultDiv = document.getElementById("result");
  resultDiv.innerHTML = "";

  if (!headers) {
    alert("Please paste the raw email headers!");
    return;
  }

  resultDiv.textContent = "Checking...";

  try {
    const formData = new URLSearchParams();
    formData.append("raw_headers", headers);

    const response = await fetch("http://127.0.0.1:8000/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formData.toString(),
    });

    const data = await response.json();

    if (response.ok) {
      resultDiv.innerHTML = `
        <p><strong>Status:</strong> <span style="color:${data.status === "Legit" ? "green" : "red"}">${data.status}</span></p>
        <p><strong>SPF:</strong> ${data.spf}</p>
        <p><strong>DKIM:</strong> ${data.dkim}</p>
        <p><strong>DMARC:</strong> ${data.dmarc}</p>
      `;
    } else {
      resultDiv.innerHTML = `<p style="color:red;"><strong>Error:</strong> ${JSON.stringify(data)}</p>`;
    }
  } catch (err) {
    resultDiv.innerHTML = `<p style="color:red;"><strong>Error:</strong> ${err.message}</p>`;
  }
});
