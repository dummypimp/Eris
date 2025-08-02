import React from "react";

export default function ActionPanel({ device }) {
  const onActionClick = (action) => {
    alert(`Action "${action}" triggered for device ${device.display_id || device.id}`);
    // Here connect to mythic mutation/task mutation for live commands
  };

  return (
    <div>
      <h2>Live Actions for {device.description || device.display_id}</h2>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        {["Overlay", "Frida Inject", "Screenshot", "Audio Record", "File Exfil", "Location Ping"].map(
          (action) => (
            <button
              key={action}
              onClick={() => onActionClick(action)}
              style={{
                padding: "12px 18px",
                borderRadius: 6,
                cursor: "pointer",
                backgroundColor: "#1067d6",
                color: "white",
                border: "none",
                minWidth: 120,
                fontWeight: "bold",
              }}
            >
              {action}
            </button>
          )
        )}
      </div>
    </div>
  );
}
