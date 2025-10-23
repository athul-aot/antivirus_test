import { useState } from "react";
import { useRouter } from "next/router";
import styles from "../../styles/Home.module.css";

const apiEndpoints = {
  virustotal: "http://localhost:8000/scan",
  cloudmersive: "http://localhost:8000/scan/cloudmersive"
};

export default function Scanner() {
  const router = useRouter();
  const { provider } = router.query;

  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  if (!provider) return null;

  const handleFileChange = (e) => setFile(e.target.files[0]);

  const handleScan = async () => {
    if (!file) {
      alert("Please choose a file first!");
      return;
    }
    setLoading(true);
    setResult(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(apiEndpoints[provider], {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      setResult(data);
    } catch (e) {
      alert("Error scanning file");
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "linear-gradient(to right, #e0eafc, #cfdef3)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontFamily: "Inter, Arial, sans-serif",
      }}
    >
      <div className={styles.scannerCard}>
        <h1 style={{ fontSize: 28, marginBottom: 8 }}>
          {provider === "virustotal" && "🦠 VirusTotal File Scanner"}
          {provider === "cloudmersive" && "🌩️ Cloudmersive File Scanner"}
        </h1>
        <label className={styles.fileUploadLabel}>
          {file ? file.name : "Choose a file"}
          <input
            type="file"
            onChange={handleFileChange}
            className={styles.hiddenFileInput}
          />
        </label>
        <button
          className={styles.scanBtn}
          onClick={handleScan}
          disabled={loading}
        >
          {loading ? "Scanning..." : "Scan File"}
        </button>

        {result && (
          <div style={{ marginTop: 34, borderTop: "1px solid #e9e9e9" }}>
            <div
              className={styles.verdictBadge}
              style={{
                background:
                  result.verdict && result.verdict.includes("Malicious")
                    ? "#ff4d4f"
                    : "#52c41a",
              }}
            >
              {result.verdict}
            </div>

            {result.message && (
              <p style={{ color: "#faad14" }}>{result.message}</p>
            )}

            {result.stats && (
              <>
                <h3>Detection Stats</h3>
                <ul>
                  <li>Malicious: <b>{result.stats.malicious}</b></li>
                  <li>Suspicious: <b>{result.stats.suspicious}</b></li>
                  <li>Undetected: <b>{result.stats.undetected}</b></li>
                  <li>Harmless: <b>{result.stats.harmless}</b></li>
                  <li>Timeout: <b>{result.stats.timeout}</b></li>
                  <li>Type Unsupported: <b>{result.stats.type_unsupported}</b></li>
                  <li>Failure: <b>{result.stats.failure}</b></li>
                </ul>

                <h3>Detailed Engine Results</h3>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead style={{ backgroundColor: "#f0f0f0" }}>
                    <tr>
                      <th style={{ padding: "8px", border: "1px solid #ddd" }}>Engine</th>
                      <th style={{ padding: "8px", border: "1px solid #ddd" }}>Category</th>
                      <th style={{ padding: "8px", border: "1px solid #ddd" }}>Result</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.results?.map((r, i) => (
                      <tr key={i}>
                        <td style={{ padding: "8px", border: "1px solid #ddd" }}>{r.engine}</td>
                        <td style={{ padding: "8px", border: "1px solid #ddd" }}>{r.category}</td>
                        <td style={{ padding: "8px", border: "1px solid #ddd" }}>{r.result || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}

            <details style={{ marginTop: 12, fontSize: 13 }}>
              <summary style={{ cursor: "pointer", color: "#0070f3" }}>Show Advanced Report</summary>
              <pre style={{ whiteSpace: "pre-wrap", marginTop: 10, maxHeight: 300, overflowY: "auto" }}>
                {JSON.stringify(result.raw_report, null, 2)}
              </pre>
            </details>
          </div>
        )}
      </div>
    </div>
  );
}
