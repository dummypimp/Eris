import React, { useEffect } from "react";
import { useAppState } from "../contexts/AppStateContext";
import { useQuery } from "@apollo/client";
import { GET_CALLBACKS } from "../api/mythic";
import DeviceCard from "./DeviceCard";

export default function DashboardContainer({ onDeviceSelect }) {
  const { campaign, devices, setDevices } = useAppState();
  const { data, loading, error } = useQuery(GET_CALLBACKS, {
    variables: { campaignID: campaign },
  });

  useEffect(() => {
    if (data?.callbacks) {
      setDevices(data.callbacks);
    }
  }, [data, setDevices]);

  if (loading) return <p>Loading devices...</p>;
  if (error) return <p>Error loading devices: {error.message}</p>;

  return (
    <div>
      <h2>Connected Devices</h2>
      {devices.length === 0 ? (
        <p>No devices found</p>
      ) : (
        devices.map((device) => (
          <DeviceCard key={device.id} device={device} onClick={() => onDeviceSelect(device)} />
        ))
      )}
    </div>
  );
}
