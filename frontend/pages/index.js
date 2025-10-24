import { useRouter } from "next/router";
import styles from "../styles/Home.module.css";

// pages/index.js addition
const providers = [
  { name: "VirusTotal", id: "virustotal" },
  { name: "Cloudmersive", id: "cloudmersive" },
  { name: "ClamAV", id: "clamav" }
];


export default function ProviderSelect() {
  const router = useRouter();

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: "linear-gradient(to right, #e0eafc, #cfdef3)",
        fontFamily: "Inter, Arial, sans-serif",
      }}
    >
      <div className={styles.scannerCard}>
        <h1 style={{ fontSize: 29, marginBottom: 18 }}>Choose Antivirus Provider</h1>
        <div style={{ display: "flex", gap: "30px", justifyContent: "center" }}>
          {providers.map((prov) => (
            <div
              className={styles.providerCard}
              key={prov.id}
              onClick={() => router.push(`/scan/${prov.id}`)}
              style={{ cursor: "pointer" }}
            >
              {prov.name}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
