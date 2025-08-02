import React, { useState } from "react";
import Sidebar from "./components/Sidebar";
import NavTabs from "./components/NavTabs";
import Dashboard from "./components/Dashboard";
import Campaigns from "./components/Campaigns";
import DeviceDetail from "./components/DeviceDetail";

const TABS = ["Dashboard", "Devices", "Artifacts", "Actions", "Timeline", "MITRE", "Campaigns", "Settings"];

export default function App() {
  const [currentTab, setCurrentTab] = useState("Dashboard");
  const [selectedDevice, setSelectedDevice] = useState(null);

  return (
    <div style={{ display: "flex", height: "100vh", fontFamily: "'Lexend Tera', monospace" }}>
      <Sidebar selectedDevice={selectedDevice} onDeviceSelect={setSelectedDevice} currentTab={currentTab} />
      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        <NavTabs tabs={TABS} currentTab={currentTab} onTabChange={setCurrentTab} />
        <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
          {currentTab === "Dashboard" && <Dashboard onDeviceSelect={setSelectedDevice} />}
          {currentTab === "Devices" && selectedDevice && <DeviceDetail device={selectedDevice} />}
          {currentTab === "Artifacts" && <div>Artifact list component</div>}
          {currentTab === "Actions" && selectedDevice && <div>Device actions component</div>}
          {currentTab === "Timeline" && selectedDevice && <div>Timeline component</div>}
          {currentTab === "MITRE" && <div>MITRE matrix component</div>}
          {currentTab === "Campaigns" && <Campaigns />}
          {currentTab === "Settings" && <div>Settings page</div>}
        </div>
      </div>
    </div>
  );
}
