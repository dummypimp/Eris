"use client"

import {
    Sheet,
    SheetContent,
    SheetDescription,
    SheetHeader,
    SheetTitle,
    SheetTrigger,
  } from "@/components/ui/sheet"
import { Button } from "@/components/ui/button"
import { Settings as SettingsIcon, Smartphone, Trash, Plus } from "lucide-react"
import {
    Accordion,
    AccordionContent,
    AccordionItem,
    AccordionTrigger,
  } from "@/components/ui/accordion"
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { useState, useEffect } from "react";
import type { Device } from "@/lib/types";
import { ScrollArea } from "./ui/scroll-area";
import { Textarea } from "./ui/textarea";

interface SettingsProps {
  onDeviceDeselect: () => void;
}

const getDeviceConfig = (device: Device) => {
  return JSON.stringify({
    guid: device.guid,
    name: device.name,
    os: device.os,
    ip: device.ip,
    connectionType: device.connectionType,
    callback_interval: 60,
    callback_jitter: 10,
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
  }, null, 2);
}

export function Settings({ onDeviceDeselect }: SettingsProps) {
    const [devices, setDevices] = useState<Device[]>([]);

    const handleRemoveDevice = (guid: string) => {
        setDevices(devices.filter(d => d.guid !== guid));
        onDeviceDeselect();
    };

    return (
        <Sheet>
            <SheetTrigger asChild>
                <Button variant="outline" size="icon">
                    <SettingsIcon className="h-5 w-5" />
                    <span className="sr-only">Open Settings</span>
                </Button>
            </SheetTrigger>
            <SheetContent className="w-full sm:w-full lg:max-w-3xl p-0" side="right">
                <SheetHeader className="p-6 border-b">
                    <SheetTitle>Campaign Settings</SheetTitle>
                    <SheetDescription>
                        Manage your connected devices and campaign settings.
                    </SheetDescription>
                </SheetHeader>
                <ScrollArea className="h-[calc(100%-140px)]">
                  <div className="p-6 space-y-6">
                    <div>
                      <h3 className="text-lg font-semibold mb-4">Devices in Campaign</h3>
                      <Accordion type="single" collapsible className="w-full">
                          {devices.map((device) => (
                              <AccordionItem value={device.guid} key={device.guid}>
                                  <AccordionTrigger>
                                      <div className="flex items-center gap-4">
                                          <Smartphone />
                                          <div>
                                              <p className="font-semibold">{device.name}</p>
                                              <p className="text-xs text-muted-foreground">{device.guid}</p>
                                          </div>
                                      </div>
                                  </AccordionTrigger>
                                  <AccordionContent>
                                      <div className="space-y-4 p-4 bg-muted/30 rounded-md">
                                          <div className="grid grid-cols-2 gap-4">
                                              <div>
                                                  <Label>Callback Interval (s)</Label>
                                                  <Input defaultValue="60" />
                                              </div>
                                              <div>
                                                  <Label>Callback Jitter (%)</Label>
                                                  <Input defaultValue="10" />
                                              </div>
                                          </div>
                                          <div>
                                            <Label>JSON Configuration</Label>
                                            <Textarea
                                              defaultValue={getDeviceConfig(device)}
                                              rows={10}
                                              className="font-code text-xs"
                                            />
                                          </div>
                                          <div className="col-span-2 flex justify-end gap-2">
                                              <Button variant="outline">Pause Callback</Button>
                                              <AlertDialog>
                                                <AlertDialogTrigger asChild>
                                                  <Button variant="destructive">
                                                    <Trash className="mr-2 h-4 w-4" />
                                                    Remove Device
                                                  </Button>
                                                </AlertDialogTrigger>
                                                <AlertDialogContent>
                                                  <AlertDialogHeader>
                                                    <AlertDialogTitle>Are you sure?</AlertDialogTitle>
                                                    <AlertDialogDescription>
                                                      This action cannot be undone. This will permanently remove the
                                                      device and its data.
                                                    </AlertDialogDescription>
                                                  </AlertDialogHeader>
                                                  <AlertDialogFooter>
                                                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                                                    <AlertDialogAction
                                                      className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                                      onClick={() => handleRemoveDevice(device.guid)}
                                                    >
                                                      Continue
                                                    </AlertDialogAction>
                                                  </AlertDialogFooter>
                                                </AlertDialogContent>
                                              </AlertDialog>
                                          </div>
                                      </div>
                                  </AccordionContent>
                              </AccordionItem>
                          ))}
                      </Accordion>
                    </div>
                  </div>
                </ScrollArea>
                <div className="p-4 absolute bottom-0 w-full border-t">
                    <Button variant="success" className="w-full">
                      <Plus className="mr-2 h-4 w-4"/>
                      Add New Device
                    </Button>
                </div>
            </SheetContent>
        </Sheet>
    )
}