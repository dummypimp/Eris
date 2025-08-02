import React from "react";

export default function DeviceCard({ device, selected, onClick }) {
  const statusColors = {
    online: "#00e6a7",
    idle: "#ffe350",
    offline: "#fa869b",
  };
  const statusColor = statusColors[device.status?.toLowerCase()] || "#b2bcce";

  return (
    <div
      onClick={onClick}
      style={{
        borderRadius: 10,
        padding: 12,
        marginBottom: 12,
        cursor: "pointer",
        backgroundColor: selected ? "#104e8b" : "#2c3e5a",
        border: selected ? `2px solid ${statusColor}` : "none",
        color: "white",
      }}
    >
      <div
        style={{
          fontSize: 14,
          fontWeight: "bold",
          marginBottom: 4,
        }}
      >
        {device.description || device.display_id}
      </div>
      <div style={{ fontSize: 12, color: statusColor }}>
        Status: {device.status || "unknown"}
      </div>
      <div style={{ fontSize: 11, color: "#a3b1cc", marginTop: 4 }}>
        Last Check-in: {device.last_checkin || "--"}
      </div>
    </div>
  );
}
