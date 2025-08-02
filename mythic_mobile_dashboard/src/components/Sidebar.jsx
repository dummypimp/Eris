import React from "react";

export default function Sidebar({ selectedDevice, onDeviceSelect, currentTab }) {
  // For demo, dummy device list; in production, hook to backend
  const devices = [
    { id: "d1", description: "Pixel 6 Pro", last_checkin: "2 min ago", status: "online" },
    { id: "d2", description: "Samsung S21", last_checkin: "15 min ago", status: "idle" },
  ];

  return (
    <aside style={{
      width: 280, backgroundColor: "#1f2a44", color: "white",
      padding: 16, overflowY: "auto"
    }}>
      <h3 style={{ marginBottom: 16 }}>Devices</h3>
      {devices.map((d) => (
        <div
          key={d.id}
          onClick={() => onDeviceSelect(d)}
          style={{
            padding: 10,
            marginBottom: 12,
            borderRadius: 8,
            cursor: "pointer",
            backgroundColor: selectedDevice?.id === d.id ? "#104e8b" : "#2c3e5a",
            border: selectedDevice?.id === d.id ? "2px solid #00e6a7" : "none",
            position: "relative"
          }}
        >
          <div style={{ fontWeight: "bold", fontSize: 14 }}>{d.description}</div>
          <div style={{ fontSize: 12, color: "#71b3df" }}>Last check-in: {d.last_checkin}</div>
          <div style={{
            position: "absolute", top: 8, right: 8,
            width: 10, height: 10,
            borderRadius: "50%",
            backgroundColor: d.status === "online" ? "#00e6a7" : d.status === "idle" ? "#ffe350" : "#fa869b"
          }} />
        </div>
      ))}
    </aside>
  );
}
