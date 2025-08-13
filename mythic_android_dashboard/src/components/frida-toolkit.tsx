'use client';

import React from 'react';
import {
  Play,
  Square,
  Cpu,
  Smartphone,
  Code,
  Activity,
  Eye,
  Shield,
  Lock,
  Camera,
  Mic,
  MessageSquare,
  Phone,
  MapPin,
  Wifi,
  Settings,
  Download,
  Upload,
  Trash2,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  XCircle,
  Clock,
  FileCode,
  Terminal,
  Zap,
  Target,
  Bug,
  HardDrive,
  Network,
  KeyRound
} from 'lucide-react';

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
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

import type { 
  Device, 
  FridaSession, 
  FridaScript, 
  FridaServerStatus, 
  FridaProcess, 
  FridaHook, 
  FridaCommand 
} from '@/lib/types';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';

interface FridaToolkitProps {
  device: Device;
}

// Predefined Frida scripts that match the payload APK capabilities
const PREDEFINED_SCRIPTS = [
  {
    id: 'ssl-bypass',
    name: 'SSL Pinning Bypass',
    description: 'Bypass SSL certificate pinning for network analysis',
    category: 'Network',
    icon: <Lock className="h-4 w-4" />,
    tags: ['ssl', 'network', 'bypass']
  },
  {
    id: 'root-bypass',
    name: 'Root Detection Bypass',
    description: 'Bypass root detection mechanisms',
    category: 'System',
    icon: <Shield className="h-4 w-4" />,
    tags: ['root', 'detection', 'bypass']
  },
  {
    id: 'crypto-hooks',
    name: 'Crypto Function Hooks',
    description: 'Monitor cryptographic operations',
    category: 'Crypto',
    icon: <KeyRound className="h-4 w-4" />,
    tags: ['crypto', 'encryption', 'monitoring']
  },
  {
    id: 'basic-hooks',
    name: 'Basic Android Hooks',
    description: 'Hook common Android system functions',
    category: 'System',
    icon: <Activity className="h-4 w-4" />,
    tags: ['android', 'system', 'monitoring']
  },
  {
    id: 'camera-hooks',
    name: 'Camera API Hooks',
    description: 'Monitor camera usage and capture operations',
    category: 'Surveillance',
    icon: <Camera className="h-4 w-4" />,
    tags: ['camera', 'surveillance', 'monitoring']
  },
  {
    id: 'mic-hooks',
    name: 'Microphone API Hooks',
    description: 'Monitor microphone access and audio recording',
    category: 'Surveillance',
    icon: <Mic className="h-4 w-4" />,
    tags: ['microphone', 'audio', 'surveillance']
  },
  {
    id: 'location-hooks',
    name: 'Location Service Hooks',
    description: 'Monitor GPS and location service calls',
    category: 'Location',
    icon: <MapPin className="h-4 w-4" />,
    tags: ['location', 'gps', 'tracking']
  },
  {
    id: 'sms-hooks',
    name: 'SMS API Hooks',
    description: 'Monitor SMS sending and receiving',
    category: 'Communication',
    icon: <MessageSquare className="h-4 w-4" />,
    tags: ['sms', 'messaging', 'communication']
  },
  {
    id: 'call-hooks',
    name: 'Phone Call Hooks',
    description: 'Monitor phone call activities',
    category: 'Communication',
    icon: <Phone className="h-4 w-4" />,
    tags: ['calls', 'phone', 'communication']
  },
  {
    id: 'file-system-hooks',
    name: 'File System Hooks',
    description: 'Monitor file system operations',
    category: 'Storage',
    icon: <HardDrive className="h-4 w-4" />,
    tags: ['filesystem', 'files', 'storage']
  },
  {
    id: 'network-hooks',
    name: 'Network API Hooks',
    description: 'Monitor network connections and data transfer',
    category: 'Network',
    icon: <Network className="h-4 w-4" />,
    tags: ['network', 'http', 'data']
  },
  {
    id: 'keylogger-hooks',
    name: 'Keylogger Hooks',
    description: 'Capture keyboard input and text entry',
    category: 'Surveillance',
    icon: <Terminal className="h-4 w-4" />,
    tags: ['keylogger', 'input', 'surveillance']
  }
];

export function FridaToolkit({ device }: FridaToolkitProps) {
  const [fridaServerStatus, setFridaServerStatus] = React.useState<FridaServerStatus>({
    deviceId: device.guid,
    running: false,
    version: '16.1.4',
    port: 27042,
    activeSessions: 0,
    architecture: 'arm64',
    uptime: 0,
    lastPing: new Date().toISOString()
  });

  const [fridaSessions, setFridaSessions] = React.useState<FridaSession[]>([]);
  const [fridaScripts, setFridaScripts] = React.useState<FridaScript[]>([]);
  const [fridaProcesses, setFridaProcesses] = React.useState<FridaProcess[]>([]);
  const [fridaHooks, setFridaHooks] = React.useState<FridaHook[]>([]);
  const [isLoading, setIsLoading] = React.useState(false);
  const [selectedScript, setSelectedScript] = React.useState<string>('');
  const [customScriptContent, setCustomScriptContent] = React.useState('');
  const [selectedProcess, setSelectedProcess] = React.useState<string>('');
  const [hookClassName, setHookClassName] = React.useState('');
  const [hookMethodName, setHookMethodName] = React.useState('');
  const [scriptOutput, setScriptOutput] = React.useState<string[]>([]);
  const [activeTab, setActiveTab] = React.useState('status');
  
  const { toast } = useToast();

  // Initialize Frida server status on component mount
  React.useEffect(() => {
    checkFridaServerStatus();
    loadFridaSessions();
    loadFridaProcesses();
    
    // Set up polling for real-time updates
    const interval = setInterval(() => {
      if (fridaServerStatus.running) {
        checkFridaServerStatus();
        loadFridaSessions();
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [device.guid]);

  const checkFridaServerStatus = async () => {
    try {
      // This would call the actual API endpoint
      // For now, simulating based on device status
      const isRunning = device.status === 'active';
      
      setFridaServerStatus(prev => ({
        ...prev,
        running: isRunning,
        activeSessions: fridaSessions.length,
        uptime: isRunning ? prev.uptime + 5 : 0,
        lastPing: new Date().toISOString()
      }));
    } catch (error) {
      console.error('Failed to check Frida server status:', error);
    }
  };

  const toggleFridaServer = async () => {
    setIsLoading(true);
    try {
      const action = fridaServerStatus.running ? 'stop' : 'start';
      
      // Simulate API call to start/stop Frida server
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      setFridaServerStatus(prev => ({
        ...prev,
        running: !prev.running,
        uptime: prev.running ? 0 : prev.uptime
      }));
      
      toast({
        title: `Frida Server ${action === 'start' ? 'Started' : 'Stopped'}`,
        description: `Frida server has been ${action}ed on device ${device.name}`
      });
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Failed to toggle Frida server'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const loadFridaSessions = async () => {
    try {
      // Mock data - replace with actual API call
      const mockSessions: FridaSession[] = [
        {
          id: 'session_1',
          deviceId: device.guid,
          targetPackage: 'com.android.systemservice',
          created: new Date().toISOString(),
          status: 'active',
          attached: true,
          scripts: []
        }
      ];
      
      setFridaSessions(mockSessions);
    } catch (error) {
      console.error('Failed to load Frida sessions:', error);
    }
  };

  const loadFridaProcesses = async () => {
    try {
      // Mock data - replace with actual API call
      const mockProcesses: FridaProcess[] = [
        { pid: 1234, name: 'com.android.systemservice', package: 'com.android.systemservice', user: 'system' },
        { pid: 5678, name: 'com.whatsapp', package: 'com.whatsapp', user: 'u0_a123' },
        { pid: 9012, name: 'com.instagram.android', package: 'com.instagram.android', user: 'u0_a124' },
        { pid: 3456, name: 'com.android.chrome', package: 'com.android.chrome', user: 'u0_a125' },
      ];
      
      setFridaProcesses(mockProcesses);
    } catch (error) {
      console.error('Failed to load processes:', error);
    }
  };

  const executeScript = async (scriptId: string, targetPackage?: string) => {
    setIsLoading(true);
    try {
      const script = PREDEFINED_SCRIPTS.find(s => s.id === scriptId);
      if (!script) {
        throw new Error('Script not found');
      }

      // Simulate script execution
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      const newScript: FridaScript = {
        id: `script_${Date.now()}`,
        name: script.name,
        type: 'predefined',
        description: script.description,
        content: `// ${script.name}\nconsole.log('${script.description} executed');`,
        status: 'running',
        injected: true,
        targetPackage: targetPackage || 'com.android.systemservice',
        lastExecuted: new Date().toISOString(),
        output: [`[${new Date().toLocaleTimeString()}] ${script.name} executed successfully`]
      };
      
      setFridaScripts(prev => [...prev, newScript]);
      setScriptOutput(prev => [...prev, `Executed: ${script.name}`, ...newScript.output!]);
      
      toast({
        title: 'Script Executed',
        description: `${script.name} has been injected and executed`
      });
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Execution Failed',
        description: 'Failed to execute Frida script'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const executeCustomScript = async () => {
    if (!customScriptContent.trim()) {
      toast({
        variant: 'destructive',
        title: 'Empty Script',
        description: 'Please enter script content'
      });
      return;
    }

    setIsLoading(true);
    try {
      // Simulate custom script execution
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const newScript: FridaScript = {
        id: `custom_${Date.now()}`,
        name: 'Custom Script',
        type: 'custom',
        description: 'User-defined Frida script',
        content: customScriptContent,
        status: 'running',
        injected: true,
        targetPackage: selectedProcess || 'com.android.systemservice',
        lastExecuted: new Date().toISOString(),
        output: [`[${new Date().toLocaleTimeString()}] Custom script executed`]
      };
      
      setFridaScripts(prev => [...prev, newScript]);
      setScriptOutput(prev => [...prev, 'Custom script executed', ...newScript.output!]);
      setCustomScriptContent('');
      
      toast({
        title: 'Custom Script Executed',
        description: 'Your custom Frida script has been executed'
      });
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Execution Failed',
        description: 'Failed to execute custom script'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const createFunctionHook = async () => {
    if (!hookClassName.trim() || !hookMethodName.trim()) {
      toast({
        variant: 'destructive',
        title: 'Missing Information',
        description: 'Please enter both class name and method name'
      });
      return;
    }

    setIsLoading(true);
    try {
      // Simulate hook creation
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const newHook: FridaHook = {
        id: `hook_${Date.now()}`,
        sessionId: fridaSessions[0]?.id || 'default',
        className: hookClassName,
        methodName: hookMethodName,
        hookType: 'before',
        active: true,
        hitCount: 0,
        script: `// Hook for ${hookClassName}.${hookMethodName}\nJava.perform(function() {\n    var ${hookClassName.split('.').pop()} = Java.use("${hookClassName}");\n    ${hookClassName.split('.').pop()}.${hookMethodName}.implementation = function() {\n        console.log("[+] ${hookClassName}.${hookMethodName} called");\n        return this.${hookMethodName}.apply(this, arguments);\n    };\n});`
      };
      
      setFridaHooks(prev => [...prev, newHook]);
      setScriptOutput(prev => [...prev, `Created hook: ${hookClassName}.${hookMethodName}`]);
      setHookClassName('');
      setHookMethodName('');
      
      toast({
        title: 'Hook Created',
        description: `Function hook created for ${hookClassName}.${hookMethodName}`
      });
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Hook Creation Failed',
        description: 'Failed to create function hook'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const removeScript = (scriptId: string) => {
    setFridaScripts(prev => prev.filter(script => script.id !== scriptId));
    setScriptOutput(prev => [...prev, `Script ${scriptId} removed`]);
    
    toast({
      title: 'Script Removed',
      description: 'Frida script has been unloaded'
    });
  };

  const removeHook = (hookId: string) => {
    setFridaHooks(prev => prev.filter(hook => hook.id !== hookId));
    setScriptOutput(prev => [...prev, `Hook ${hookId} removed`]);
    
    toast({
      title: 'Hook Removed',
      description: 'Function hook has been removed'
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'running':
      case 'active':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'stopped':
      case 'inactive':
        return <XCircle className="h-4 w-4 text-red-500" />;
      case 'error':
        return <AlertCircle className="h-4 w-4 text-yellow-500" />;
      default:
        return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Frida Server Status Card */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Cpu className="h-5 w-5" />
              Frida Server Status
            </CardTitle>
            <CardDescription>
              Embedded Frida server running on {device.name}
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={fridaServerStatus.running ? "success" : "secondary"}>
              {fridaServerStatus.running ? 'Running' : 'Stopped'}
            </Badge>
            <Button
              onClick={toggleFridaServer}
              disabled={isLoading}
              size="sm"
              variant={fridaServerStatus.running ? "destructive" : "default"}
            >
              {isLoading ? (
                <RefreshCw className="h-4 w-4 animate-spin mr-2" />
              ) : fridaServerStatus.running ? (
                <Square className="h-4 w-4 mr-2" />
              ) : (
                <Play className="h-4 w-4 mr-2" />
              )}
              {fridaServerStatus.running ? 'Stop' : 'Start'} Server
            </Button>
          </div>
        </CardHeader>
        {fridaServerStatus.running && (
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <Label className="text-muted-foreground">Version</Label>
                <p className="font-medium">{fridaServerStatus.version}</p>
              </div>
              <div>
                <Label className="text-muted-foreground">Port</Label>
                <p className="font-medium">{fridaServerStatus.port}</p>
              </div>
              <div>
                <Label className="text-muted-foreground">Architecture</Label>
                <p className="font-medium">{fridaServerStatus.architecture}</p>
              </div>
              <div>
                <Label className="text-muted-foreground">Active Sessions</Label>
                <p className="font-medium">{fridaServerStatus.activeSessions}</p>
              </div>
            </div>
          </CardContent>
        )}
      </Card>

      {/* Main Frida Toolkit Tabs */}
      {fridaServerStatus.running && (
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="scripts">Scripts</TabsTrigger>
            <TabsTrigger value="hooks">Hooks</TabsTrigger>
            <TabsTrigger value="processes">Processes</TabsTrigger>
            <TabsTrigger value="sessions">Sessions</TabsTrigger>
            <TabsTrigger value="console">Console</TabsTrigger>
          </TabsList>

          {/* Scripts Tab */}
          <TabsContent value="scripts" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Predefined Scripts */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <FileCode className="h-4 w-4" />
                    Predefined Scripts
                  </CardTitle>
                  <CardDescription>
                    Ready-to-use Frida scripts for common tasks
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[400px]">
                    <div className="space-y-2">
                      {PREDEFINED_SCRIPTS.map((script) => (
                        <Card key={script.id} className="p-3">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start gap-3">
                              {script.icon}
                              <div>
                                <h4 className="font-medium text-sm">{script.name}</h4>
                                <p className="text-xs text-muted-foreground">{script.description}</p>
                                <div className="flex gap-1 mt-1">
                                  {script.tags.map(tag => (
                                    <Badge key={tag} variant="outline" className="text-xs">
                                      {tag}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            </div>
                            <Button
                              size="sm"
                              onClick={() => executeScript(script.id)}
                              disabled={isLoading}
                            >
                              <Zap className="h-3 w-3 mr-1" />
                              Execute
                            </Button>
                          </div>
                        </Card>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>

              {/* Custom Script */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Code className="h-4 w-4" />
                    Custom Script
                  </CardTitle>
                  <CardDescription>
                    Write and execute your own Frida scripts
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label htmlFor="target-process">Target Process</Label>
                    <Select value={selectedProcess} onValueChange={setSelectedProcess}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select target process" />
                      </SelectTrigger>
                      <SelectContent>
                        {fridaProcesses.map((process) => (
                          <SelectItem key={process.pid} value={process.name}>
                            {process.name} (PID: {process.pid})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="custom-script">Script Content</Label>
                    <Textarea
                      id="custom-script"
                      value={customScriptContent}
                      onChange={(e) => setCustomScriptContent(e.target.value)}
                      placeholder="Java.perform(function() {&#10;    // Your Frida script here&#10;    console.log('Hello from Frida!');&#10;});"
                      className="font-mono text-sm"
                      rows={10}
                    />
                  </div>
                  <Button
                    onClick={executeCustomScript}
                    disabled={isLoading || !customScriptContent.trim()}
                    className="w-full"
                  >
                    {isLoading ? (
                      <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                    ) : (
                      <Play className="h-4 w-4 mr-2" />
                    )}
                    Execute Custom Script
                  </Button>
                </CardContent>
              </Card>
            </div>

            {/* Active Scripts */}
            {fridaScripts.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Active Scripts</CardTitle>
                  <CardDescription>
                    Currently running Frida scripts
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Target</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Last Executed</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {fridaScripts.map((script) => (
                        <TableRow key={script.id}>
                          <TableCell className="font-medium">{script.name}</TableCell>
                          <TableCell>
                            <Badge variant={script.type === 'predefined' ? 'default' : 'secondary'}>
                              {script.type}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-sm">{script.targetPackage}</TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {getStatusIcon(script.status)}
                              {script.status}
                            </div>
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {script.lastExecuted ? new Date(script.lastExecuted).toLocaleString() : 'Never'}
                          </TableCell>
                          <TableCell>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => removeScript(script.id)}
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Hooks Tab */}
          <TabsContent value="hooks" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Create Hook */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Target className="h-4 w-4" />
                    Create Function Hook
                  </CardTitle>
                  <CardDescription>
                    Hook specific Java methods for monitoring
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label htmlFor="hook-class">Class Name</Label>
                    <Input
                      id="hook-class"
                      value={hookClassName}
                      onChange={(e) => setHookClassName(e.target.value)}
                      placeholder="com.example.MyClass"
                      className="font-mono"
                    />
                  </div>
                  <div>
                    <Label htmlFor="hook-method">Method Name</Label>
                    <Input
                      id="hook-method"
                      value={hookMethodName}
                      onChange={(e) => setHookMethodName(e.target.value)}
                      placeholder="methodName"
                      className="font-mono"
                    />
                  </div>
                  <Button
                    onClick={createFunctionHook}
                    disabled={isLoading || !hookClassName.trim() || !hookMethodName.trim()}
                    className="w-full"
                  >
                    {isLoading ? (
                      <RefreshCw className="h-4 w-4 animate-spin mr-2" />
                    ) : (
                      <Bug className="h-4 w-4 mr-2" />
                    )}
                    Create Hook
                  </Button>
                </CardContent>
              </Card>

              {/* Hook Templates */}
              <Card>
                <CardHeader>
                  <CardTitle>Common Hook Templates</CardTitle>
                  <CardDescription>
                    Pre-configured hooks for common Android APIs
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[300px]">
                    <div className="space-y-2">
                      {[
                        { name: 'Activity.onCreate', class: 'android.app.Activity', method: 'onCreate' },
                        { name: 'System.exit', class: 'java.lang.System', method: 'exit' },
                        { name: 'File.exists', class: 'java.io.File', method: 'exists' },
                        { name: 'Runtime.exec', class: 'java.lang.Runtime', method: 'exec' },
                        { name: 'Cipher.doFinal', class: 'javax.crypto.Cipher', method: 'doFinal' },
                      ].map((template) => (
                        <div key={template.name} className="flex items-center justify-between p-2 border rounded">
                          <div>
                            <p className="font-medium text-sm">{template.name}</p>
                            <p className="text-xs text-muted-foreground font-mono">{template.class}.{template.method}</p>
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              setHookClassName(template.class);
                              setHookMethodName(template.method);
                            }}
                          >
                            Use
                          </Button>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>

            {/* Active Hooks */}
            {fridaHooks.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Active Hooks</CardTitle>
                  <CardDescription>
                    Currently active function hooks
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Class</TableHead>
                        <TableHead>Method</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Hit Count</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {fridaHooks.map((hook) => (
                        <TableRow key={hook.id}>
                          <TableCell className="font-mono text-sm">{hook.className}</TableCell>
                          <TableCell className="font-mono text-sm">{hook.methodName}</TableCell>
                          <TableCell>
                            <Badge variant="outline">{hook.hookType}</Badge>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {getStatusIcon(hook.active ? 'active' : 'inactive')}
                              {hook.active ? 'Active' : 'Inactive'}
                            </div>
                          </TableCell>
                          <TableCell>{hook.hitCount}</TableCell>
                          <TableCell>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => removeHook(hook.id)}
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Processes Tab */}
          <TabsContent value="processes">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Smartphone className="h-4 w-4" />
                    Running Processes
                  </CardTitle>
                  <CardDescription>
                    All processes running on the device
                  </CardDescription>
                </div>
                <Button onClick={loadFridaProcesses} size="sm" variant="outline">
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Refresh
                </Button>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>PID</TableHead>
                      <TableHead>Process Name</TableHead>
                      <TableHead>Package</TableHead>
                      <TableHead>User</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {fridaProcesses.map((process) => (
                      <TableRow key={process.pid}>
                        <TableCell className="font-mono">{process.pid}</TableCell>
                        <TableCell className="font-medium">{process.name}</TableCell>
                        <TableCell className="font-mono text-sm">{process.package}</TableCell>
                        <TableCell className="text-sm">{process.user}</TableCell>
                        <TableCell>
                          <div className="flex gap-2">
                            <Button size="sm" variant="outline">
                              <Eye className="h-3 w-3 mr-1" />
                              Attach
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Sessions Tab */}
          <TabsContent value="sessions">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  Frida Sessions
                </CardTitle>
                <CardDescription>
                  Active Frida debugging sessions
                </CardDescription>
              </CardHeader>
              <CardContent>
                {fridaSessions.length > 0 ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Session ID</TableHead>
                        <TableHead>Target Package</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Created</TableHead>
                        <TableHead>Scripts</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {fridaSessions.map((session) => (
                        <TableRow key={session.id}>
                          <TableCell className="font-mono text-sm">{session.id}</TableCell>
                          <TableCell className="font-mono text-sm">{session.targetPackage}</TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              {getStatusIcon(session.status)}
                              {session.status}
                            </div>
                          </TableCell>
                          <TableCell className="text-sm">
                            {new Date(session.created).toLocaleString()}
                          </TableCell>
                          <TableCell>{session.scripts.length}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Activity className="h-8 w-8 mx-auto mb-2" />
                    <p>No active Frida sessions</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Console Tab */}
          <TabsContent value="console">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Terminal className="h-4 w-4" />
                  Frida Console Output
                </CardTitle>
                <CardDescription>
                  Real-time output from Frida scripts and hooks
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px] w-full border rounded-md p-4 bg-black text-green-400 font-mono text-sm">
                  {scriptOutput.length > 0 ? (
                    scriptOutput.map((line, index) => (
                      <div key={index} className="mb-1">
                        {line}
                      </div>
                    ))
                  ) : (
                    <div className="text-gray-500">
                      Frida console output will appear here...
                    </div>
                  )}
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}
