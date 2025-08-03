
'use client';

import { useState, useEffect } from 'react';
import { DeviceSelection } from '@/components/device-selection';
import { DashboardLayout } from '@/components/dashboard-layout';
import type { Device } from '@/lib/types';

export default function Home() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);

  const handleDeviceSelect = (device: Device | null) => {
    setSelectedDevice(device);
  };

  const handleDeviceUpdate = (updatedDevice: Device) => {
    setDevices(devices.map(d => d.guid === updatedDevice.guid ? updatedDevice : d));
  };
  
  const handleDeviceRemove = (guid: string) => {
    setDevices(devices.filter(d => d.guid !== guid));
    if (selectedDevice?.guid === guid) {
      setSelectedDevice(null);
    }
  };

  if (!selectedDevice) {
    return (
      <DeviceSelection 
        devices={devices} 
        onDeviceSelect={handleDeviceSelect}
        onDeviceUpdate={handleDeviceUpdate}
        onDeviceRemove={handleDeviceRemove}
      />
    );
  }

  return (
    <DashboardLayout 
      selectedDevice={selectedDevice} 
      onDeviceSelect={handleDeviceSelect}
    />
  );
}
