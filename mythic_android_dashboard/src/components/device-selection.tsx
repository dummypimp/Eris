
'use client';

import {
  Bell,
  CheckCircle2,
  Pencil,
  Plus,
  Settings,
  Smartphone,
  XCircle,
} from 'lucide-react';
import * as React from 'react';

import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { Separator } from '@/components/ui/separator';
import type { Device } from '@/lib/types';
import { Header } from '@/components/ui/header';
import { Settings as SettingsPanel } from '@/components/settings';

interface DeviceSelectionProps {
  devices: Device[];
  onDeviceSelect: (device: Device) => void;
  onDeviceUpdate: (device: Device) => void;
  onDeviceRemove: (guid: string) => void;
}

export const DeviceSelection = ({ devices, onDeviceSelect, onDeviceUpdate, onDeviceRemove }: DeviceSelectionProps) => {
  return (
    <div className="flex min-h-screen w-full flex-col items-center justify-center bg-background p-4">
      <div className="w-full max-w-6xl">
        <Header title="Select a Device" description="Choose a device to begin monitoring and interaction.">
          <div className="flex gap-2">
            <Button variant="success">
              <Plus className="mr-2 h-4 w-4"/>
              Add Device
            </Button>
            <SettingsPanel onDeviceDeselect={() => {}} />
          </div>
        </Header>
        <Separator className="my-6" />
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {devices.map((device) => (
            <div
              key={device.guid}
              onClick={() => onDeviceSelect(device)}
              className={cn(
                'p-4 rounded-lg cursor-pointer border-2 bg-card/60 hover:border-ring/80'
              )}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Smartphone className="h-10 w-10" />
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="font-bold text-lg">{device.name}</p>
                      <Pencil className="h-4 w-4 text-muted-foreground hover:text-foreground cursor-pointer" />
                    </div>
                    <p className="text-xs text-muted-foreground">{device.guid}</p>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1">
                  {device.status === 'active' ? (
                    <CheckCircle2 className="h-5 w-5 text-success" />
                  ) : (
                    <XCircle className="h-5 w-5 text-destructive" />
                  )}
                  {device.hasNotification && <Bell className="h-5 w-5 text-warning" />}
                </div>
              </div>
              <Separator className="my-3" />
              <div className="text-sm text-muted-foreground space-y-1">
                <p>
                  <strong>IP:</strong> {device.ip}
                </p>
                <p>
                  <strong>OS:</strong> {device.os}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

    