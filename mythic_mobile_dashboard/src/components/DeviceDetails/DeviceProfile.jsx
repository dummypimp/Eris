import React from "react";

export default function DeviceProfile({ device, tab }) {
  return (
    <div>
      <h2>Device Details: {device.description || device.display_id}</h2>
      {(!tab || tab === "profile") && (
        <div>
          <p><strong>Operating System:</strong> {device.os}</p>
          <p><strong>Host:</strong> {device.host}</p>
          <p><strong>IP Address:</strong> {device.ip || "N/A"}</p>
          <p><strong>Last Check-in:</strong> {device.last_checkin}</p>
        </div>
      )}
      {tab === "timeline" && <div>Timeline panel coming soon.</div>}
    </div>
  );
}
