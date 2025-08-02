import React, { createContext, useContext, useState } from "react";

const AppStateContext = createContext();

export const AppStateProvider = ({ children }) => {
  const [campaign, setCampaign] = useState("redteam_july2025");
  const [devices, setDevices] = useState([]);
  const [artifacts, setArtifacts] = useState([]);

  return (
    <AppStateContext.Provider
      value={{
        campaign,
        setCampaign,
        devices,
        setDevices,
        artifacts,
        setArtifacts,
      }}
    >
      {children}
    </AppStateContext.Provider>
  );
};

export const useAppState = () => useContext(AppStateContext);
