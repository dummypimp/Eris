import React from "react";

export default function ArtifactList() {
  // Stub: In prod, pull via Mythic API filtered by campaign/device
  const artifacts = [
    { id: 1, type: "Screenshot", desc: "Instagram chat - Jul 26" },
    { id: 2, type: "VoIP Call Log", desc: "+1-555-1234 to +1-555-4321" },
    { id: 3, type: "Offline Log", desc: "Campaign redteam_july2025 (Jul 24)" },
  ];

  return (
    <div>
      <h2>Artifact Gallery</h2>
      {artifacts.map((art) => (
        <div
          key={art.id}
          style={{
            backgroundColor: "#1d2a44",
            padding: 12,
            marginBottom: 10,
            borderRadius: 8,
            color: "#acd8ff",
            cursor: "pointer",
          }}
          title={`${art.type}: ${art.desc}`}
        >
          <strong>{art.type}:</strong> {art.desc}
        </div>
      ))}
    </div>
  );
}
