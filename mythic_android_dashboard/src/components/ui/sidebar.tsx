
'use client';

import {
  Bell,
  CheckCircle2,
  Plus,
  Smartphone,
  XCircle,
} from 'lucide-react';
import * as React from 'react';

import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { Separator } from './separator';
import type { Device } from '@/lib/types';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetTrigger } from './sheet';
import { ScrollArea } from './scroll-area';


interface SidebarProps {
    selectedDeviceGuid: string;
    onDeviceSelect: (device: Device) => void;
    children: React.ReactNode;
}


export const Sidebar = ({selectedDeviceGuid, onDeviceSelect, children}: SidebarProps) => {
  const [devices, setDevices] = React.useState<Device[]>([]);
  return (
    <Sheet>
        <SheetTrigger asChild>
            {children}
        </SheetTrigger>
        <SheetContent side="left" className="w-80 p-0">
            <SheetHeader className='p-4'>
                <SheetTitle>Devices</SheetTitle>
            </SheetHeader>
            <Separator />
            <ScrollArea className="flex-1 h-[calc(100%-140px)]">
                <div className="space-y-2 p-4">
                    {devices.map((device) => (
                    <div
                        key={device.guid}
                        onClick={() => onDeviceSelect(device)}
                        className={cn(
                        'p-4 rounded-lg cursor-pointer border-2',
                        selectedDeviceGuid === device.guid
                            ? 'bg-ring/20 border-ring'
                            : 'bg-muted/30 border-transparent hover:border-ring/50'
                        )}
                    >
                        <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <Smartphone className="h-8 w-8" />
                            <div>
                            <p className="font-bold text-lg">{device.name}</p>
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
                        <div className="text-xs text-muted-foreground space-y-1">
                            <p><strong>IP:</strong> {device.ip}</p>
                            <p><strong>OS:</strong> {device.os}</p>
                        </div>
                    </div>
                    ))}
                </div>
            </ScrollArea>
             <div className="p-4 absolute bottom-0 w-full border-t">
                <Button variant="success" className="w-full">
                    <Plus className="mr-2 h-4 w-4"/>
                    Add Device
                </Button>
            </div>
        </SheetContent>
    </Sheet>
  );
};
