import React from "react";
import { useAppState } from "../contexts/AppStateContext";

export default function CampaignManager() {
  const { campaign, setCampaign } = useAppState();
  const campaigns = ["redteam_july2025", "internal_test_campaign", "finance_ops_aug2025"];

  return (
    <div>
      <h2>Campaign Manager</h2>
      {campaigns.map((c) => (
        <div
          key={c}
          onClick={() => setCampaign(c)}
          style={{
            margin: "8px 0",
            padding: 10,
            borderRadius: 8,
            backgroundColor: campaign === c ? "#1e74f1" : "#294163",
            color: "white",
            cursor: "pointer",
            userSelect: "none",
            fontWeight: campaign === c ? "bold" : "normal",
          }}
        >
          {c}
        </div>
      ))}
    </div>
  );
}
