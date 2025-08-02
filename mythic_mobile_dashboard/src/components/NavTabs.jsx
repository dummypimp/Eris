import React from "react";

export default function NavTabs({ tabs, currentTab, onTabChange }) {
  return (
    <nav style={{ display: "flex", backgroundColor: "#223b6e", padding: "8px 16px" }}>
      {tabs.map((tab) => (
        <button
          key={tab}
          onClick={() => onTabChange(tab)}
          style={{
            padding: "8px 16px",
            marginRight: 8,
            border: "none",
            borderRadius: 4,
            backgroundColor: currentTab === tab ? "#105ea8" : "transparent",
            color: currentTab === tab ? "white" : "#a0b0d5",
            cursor: "pointer",
            fontWeight: currentTab === tab ? "bold" : "normal"
          }}
        >
          {tab}
        </button>
      ))}
    </nav>
  );
}
