'use client';

import {
  Activity,
  Battery,
  CheckCircle2,
  HardDrive,
  Info,
  MapPin,
  Network,
  Phone,
  Shield,
  Smartphone,
  Wifi,
  XCircle,
  AlertTriangle,
  Clock,
  Cpu,
  Memory,
} from 'lucide-react';
import * as React from 'react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import type { Device } from '@/lib/types';

interface DeviceDetailsProps {
  device: Device;
  onDeviceUpdate?: (device: Device) => void;
  onClose?: () => void;
}

export const DeviceDetails = ({ device, onDeviceUpdate, onClose }: DeviceDetailsProps) => {
  const detailedInfo = device.detailed_info || {};
  const hardware = detailedInfo.hardware || {};
  const network = detailedInfo.network || {};
  const security = detailedInfo.security || {};
  const performance = detailedInfo.performance || {};
  const androidVersion = detailedInfo.android_version || {};
  const systemSettings = detailedInfo.system_settings || {};
  const location = detailedInfo.location || {};
  const connectivity = detailedInfo.connectivity || {};

  const formatBytes = (bytes: number) => {
    if (!bytes) return 'Unknown';
    const gb = bytes / (1024 * 1024 * 1024);
    if (gb >= 1) return `${gb.toFixed(1)} GB`;
    const mb = bytes / (1024 * 1024);
    return `${mb.toFixed(0)} MB`;
  };

  const getBatteryColor = (level: number) => {
    if (level > 60) return 'text-green-500';
    if (level > 30) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getComplianceColor = (score: number) => {
    if (score >= 80) return 'text-green-500';
    if (score >= 60) return 'text-yellow-500';
    return 'text-red-500';
  };

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      {}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="relative">
            <Smartphone className="h-12 w-12" />
            {device.status === 'active' ? (
              <CheckCircle2 className="absolute -top-1 -right-1 h-5 w-5 text-green-500" />
            ) : (
              <XCircle className="absolute -top-1 -right-1 h-5 w-5 text-red-500" />
            )}
          </div>
          <div>
            <h1 className="text-2xl font-bold">{device.name}</h1>
            <p className="text-muted-foreground">{device.guid}</p>
            <div className="flex items-center gap-2 mt-1">
              <Badge variant={device.status === 'active' ? 'default' : 'destructive'}>
                {device.status}
              </Badge>
              {device.campaign && (
                <Badge variant="outline">Campaign: {device.campaign}</Badge>
              )}
            </div>
          </div>
        </div>
        {onClose && (
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        )}
      </div>

      <Separator />

      {}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <Battery className={`h-5 w-5 ${getBatteryColor(device.batteryLevel || 0)}`} />
              <div>
                <p className="text-sm text-muted-foreground">Battery</p>
                <p className="font-semibold">{device.batteryLevel || 'Unknown'}%</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <HardDrive className="h-5 w-5" />
              <div>
                <p className="text-sm text-muted-foreground">Storage</p>
                <p className="font-semibold">
                  {device.storageUsed && device.storageTotal
                    ? `${((device.storageUsed / device.storageTotal) * 100).toFixed(0)}%`
                    : 'Unknown'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <Wifi className="h-5 w-5" />
              <div>
                <p className="text-sm text-muted-foreground">Connection</p>
                <p className="font-semibold">{device.connectionType}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              <div>
                <p className="text-sm text-muted-foreground">Last Seen</p>
                <p className="font-semibold text-xs">{device.lastSeen}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {}
      <Tabs defaultValue="hardware" className="w-full">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="hardware">Hardware</TabsTrigger>
          <TabsTrigger value="network">Network</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="system">System</TabsTrigger>
          <TabsTrigger value="location">Location</TabsTrigger>
        </TabsList>

        {}
        <TabsContent value="hardware" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Smartphone className="h-5 w-5" />
                  Device Information
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Manufacturer:</span>
                  <span>{hardware.manufacturer || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Model:</span>
                  <span>{hardware.model || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Brand:</span>
                  <span>{hardware.brand || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Board:</span>
                  <span>{hardware.board || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Hardware:</span>
                  <span>{hardware.hardware || 'Unknown'}</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Cpu className="h-5 w-5" />
                  Processor
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Architecture:</span>
                  <span>{hardware.cpu_architecture || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">CPU Cores:</span>
                  <span>{hardware.cpu_cores || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">ABI:</span>
                  <span>{hardware.cpu_abi || 'Unknown'}</span>
                </div>
                {performance.cpu_usage && (
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-muted-foreground">CPU Usage:</span>
                      <span>{performance.cpu_usage}%</span>
                    </div>
                    <Progress value={performance.cpu_usage} />
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Memory className="h-5 w-5" />
                  Memory
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Total Memory:</span>
                  <span>{formatBytes(hardware.memory_total)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Available:</span>
                  <span>{formatBytes(hardware.memory_available)}</span>
                </div>
                {hardware.memory_usage && (
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-muted-foreground">Memory Usage:</span>
                      <span>{hardware.memory_usage}%</span>
                    </div>
                    <Progress value={hardware.memory_usage} />
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <HardDrive className="h-5 w-5" />
                  Storage
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {hardware.storage_internal && (
                  <>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Internal Total:</span>
                      <span>{formatBytes(hardware.storage_internal.total)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Internal Used:</span>
                      <span>{formatBytes(hardware.storage_internal.used)}</span>
                    </div>
                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-muted-foreground">Internal Usage:</span>
                        <span>{hardware.storage_internal.usage_percent}%</span>
                      </div>
                      <Progress value={hardware.storage_internal.usage_percent} />
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Battery className="h-5 w-5" />
                  Battery
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Level:</span>
                  <span className={getBatteryColor(hardware.battery_level || 0)}>
                    {hardware.battery_level || 'Unknown'}%
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Status:</span>
                  <span>{hardware.battery_status || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Health:</span>
                  <span>{hardware.battery_health || 'Unknown'}</span>
                </div>
                {hardware.battery_temperature && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Temperature:</span>
                    <span>{hardware.battery_temperature}°C</span>
                  </div>
                )}
                {hardware.battery_level && (
                  <Progress value={hardware.battery_level} className="mt-2" />
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Display</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Size:</span>
                  <span>{hardware.display_size || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Resolution:</span>
                  <span>{hardware.display_resolution || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Density:</span>
                  <span>{hardware.display_density || 'Unknown'} DPI</span>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {}
        <TabsContent value="network" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Wifi className="h-5 w-5" />
                  WiFi Information
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Status:</span>
                  <span className={network.wifi_connected ? 'text-green-500' : 'text-red-500'}>
                    {network.wifi_connected ? 'Connected' : 'Disconnected'}
                  </span>
                </div>
                {network.wifi_ssid && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">SSID:</span>
                    <span>{network.wifi_ssid}</span>
                  </div>
                )}
                {network.wifi_ip_address && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">IP Address:</span>
                    <span>{network.wifi_ip_address}</span>
                  </div>
                )}
                {network.wifi_signal_strength && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Signal Strength:</span>
                    <span>{network.wifi_signal_strength} dBm</span>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Phone className="h-5 w-5" />
                  Cellular Information
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Status:</span>
                  <span className={network.cellular_connected ? 'text-green-500' : 'text-red-500'}>
                    {network.cellular_connected ? 'Connected' : 'Disconnected'}
                  </span>
                </div>
                {network.cellular_operator && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Operator:</span>
                    <span>{network.cellular_operator}</span>
                  </div>
                )}
                {network.cellular_network_type && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Network Type:</span>
                    <span>{network.cellular_network_type}</span>
                  </div>
                )}
                {network.cellular_signal_strength && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Signal Strength:</span>
                    <span>{network.cellular_signal_strength} dBm</span>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-5 w-5" />
                  Network Interfaces
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {network.ip_addresses && Object.entries(network.ip_addresses).map(([iface, ip]) => (
                  <div key={iface} className="flex justify-between">
                    <span className="text-muted-foreground">{iface}:</span>
                    <span className="font-mono text-sm">{ip}</span>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Connectivity Status</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Internet:</span>
                  <span className={connectivity.internet_connectivity ? 'text-green-500' : 'text-red-500'}>
                    {connectivity.internet_connectivity ? 'Connected' : 'Disconnected'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">DNS:</span>
                  <span className={connectivity.dns_connectivity ? 'text-green-500' : 'text-red-500'}>
                    {connectivity.dns_connectivity ? 'Working' : 'Failed'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">VPN:</span>
                  <span className={network.vpn_connected ? 'text-yellow-500' : 'text-gray-500'}>
                    {network.vpn_connected ? 'Active' : 'Inactive'}
                  </span>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {}
        <TabsContent value="security" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Security Status
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {detailedInfo.device_compliance_score && (
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-muted-foreground">Compliance Score:</span>
                      <span className={getComplianceColor(detailedInfo.device_compliance_score)}>
                        {detailedInfo.device_compliance_score}/100
                      </span>
                    </div>
                    <Progress value={detailedInfo.device_compliance_score} />
                  </div>
                )}
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Device Encrypted:</span>
                  <span className={security.device_encrypted ? 'text-green-500' : 'text-red-500'}>
                    {security.device_encrypted ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Screen Lock:</span>
                  <span className={security.screen_lock_enabled ? 'text-green-500' : 'text-red-500'}>
                    {security.screen_lock_enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Root Detected:</span>
                  <span className={security.root_detected ? 'text-red-500' : 'text-green-500'}>
                    {security.root_detected ? 'Yes' : 'No'}
                  </span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Biometric Security</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Fingerprint:</span>
                  <span className={security.fingerprint_enabled ? 'text-green-500' : 'text-gray-500'}>
                    {security.fingerprint_enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Face Unlock:</span>
                  <span className={security.face_unlock_enabled ? 'text-green-500' : 'text-gray-500'}>
                    {security.face_unlock_enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Smart Lock:</span>
                  <span className={security.smart_lock_enabled ? 'text-green-500' : 'text-gray-500'}>
                    {security.smart_lock_enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Security Patches</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Android Version:</span>
                  <span>{androidVersion.version_release || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">API Level:</span>
                  <span>{androidVersion.api_level || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Security Patch:</span>
                  <span>{androidVersion.security_patch || 'Unknown'}</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5" />
                  Threats & Risks
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Bootloader Unlocked:</span>
                  <span className={security.bootloader_unlocked ? 'text-red-500' : 'text-green-500'}>
                    {security.bootloader_unlocked ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Unknown Sources:</span>
                  <span className={security.unknown_sources_enabled ? 'text-red-500' : 'text-green-500'}>
                    {security.unknown_sources_enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">ADB Enabled:</span>
                  <span className={security.adb_enabled ? 'text-red-500' : 'text-green-500'}>
                    {security.adb_enabled ? 'Yes' : 'No'}
                  </span>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {}
        <TabsContent value="performance" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5" />
                  Current Performance
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {performance.cpu_usage && (
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-muted-foreground">CPU Usage:</span>
                      <span>{performance.cpu_usage}%</span>
                    </div>
                    <Progress value={performance.cpu_usage} />
                  </div>
                )}
                {performance.memory_usage && (
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-muted-foreground">Memory Usage:</span>
                      <span>{performance.memory_usage}%</span>
                    </div>
                    <Progress value={performance.memory_usage} />
                  </div>
                )}
                {performance.storage_usage && (
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-muted-foreground">Storage Usage:</span>
                      <span>{performance.storage_usage.internal || 0}%</span>
                    </div>
                    <Progress value={performance.storage_usage.internal || 0} />
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>System Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Processes:</span>
                  <span>{performance.process_count || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Uptime:</span>
                  <span>
                    {performance.uptime
                      ? `${Math.floor(performance.uptime / 3600)}h ${Math.floor((performance.uptime % 3600) / 60)}m`
                      : 'Unknown'
                    }
                  </span>
                </div>
                {performance.temperature && (
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Temperature:</span>
                    <span className={performance.temperature > 45 ? 'text-red-500' : 'text-green-500'}>
                      {performance.temperature}°C
                    </span>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {}
        <TabsContent value="system" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Android Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Version:</span>
                  <span>{androidVersion.version_release || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">API Level:</span>
                  <span>{androidVersion.api_level || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Build ID:</span>
                  <span>{hardware.build_id || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Kernel Version:</span>
                  <span className="font-mono text-xs">{androidVersion.kernel_version?.substring(0, 40) || 'Unknown'}</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Applications</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Total Apps:</span>
                  <span>{detailedInfo.installed_apps_count || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">System Apps:</span>
                  <span>{detailedInfo.system_apps_count || 'Unknown'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Google Play Services:</span>
                  <span className={androidVersion.google_play_services ? 'text-green-500' : 'text-red-500'}>
                    {androidVersion.google_play_services ? 'Installed' : 'Not Installed'}
                  </span>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {}
        <TabsContent value="location" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <MapPin className="h-5 w-5" />
                  Location Services
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Location Enabled:</span>
                  <span className={location.location_enabled ? 'text-green-500' : 'text-red-500'}>
                    {location.location_enabled ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">GPS Enabled:</span>
                  <span className={location.gps_enabled ? 'text-green-500' : 'text-red-500'}>
                    {location.gps_enabled ? 'Yes' : 'No'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Network Location:</span>
                  <span className={location.network_location_enabled ? 'text-green-500' : 'text-red-500'}>
                    {location.network_location_enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
              </CardContent>
            </Card>

            {device.location && (
              <Card>
                <CardHeader>
                  <CardTitle>Current Location</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Latitude:</span>
                    <span className="font-mono">{device.location.latitude?.toFixed(6)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Longitude:</span>
                    <span className="font-mono">{device.location.longitude?.toFixed(6)}</span>
                  </div>
                  {device.location.accuracy && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Accuracy:</span>
                      <span>{device.location.accuracy}m</span>
                    </div>
                  )}
                  {device.location.address && (
                    <div>
                      <span className="text-muted-foreground">Address:</span>
                      <p className="text-sm mt-1">{device.location.address}</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};