'use client';

import React, { useEffect, useRef, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Location, Device } from '@/lib/types';
import { apiClient } from '@/lib/api-client';
import { useToast } from '@/hooks/use-toast';
import {
  MapPin,
  Navigation,
  Clock,
  Route,
  Filter,
  Download,
  Refresh
} from 'lucide-react';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';

delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https:
  iconUrl: 'https:
  shadowUrl: 'https:
});

interface LocationMapProps {
  device: Device;
  height?: string;
}

interface LocationWithDevice extends Location {
  deviceId: string;
  deviceName: string;
}

export function LocationMap({ device, height = '400px' }: LocationMapProps) {
  const [locations, setLocations] = useState<LocationWithDevice[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showTrail, setShowTrail] = useState(false);
  const [timeFilter, setTimeFilter] = useState('24h');
  const [accuracy, setAccuracy] = useState('all');
  const [center, setCenter] = useState<[number, number]>([40.7128, -74.0060]);
  const [zoom, setZoom] = useState(10);
  const mapRef = useRef<L.Map | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    loadLocations();
  }, [device, timeFilter, accuracy]);

  const loadLocations = async () => {
    setIsLoading(true);
    try {
      const response = await apiClient.getLocations(device.guid, 1000);
      if (response.success && response.data) {
        const filteredLocations = filterLocationsByTime(response.data);
        const locationsWithDevice = filteredLocations.map(loc => ({
          ...loc,
          deviceId: device.guid,
          deviceName: device.name,
        }));

        setLocations(locationsWithDevice);

        if (locationsWithDevice.length > 0) {
          const latest = locationsWithDevice[0];
          setCenter([latest.latitude, latest.longitude]);
          setZoom(15);
        }
      } else {
        toast({
          variant: 'destructive',
          title: 'Error',
          description: response.error || 'Failed to load locations',
        });
      }
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Failed to load locations',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const filterLocationsByTime = (locations: Location[]): Location[] => {
    const now = Date.now();
    let cutoff = 0;

    switch (timeFilter) {
      case '1h':
        cutoff = now - (1 * 60 * 60 * 1000);
        break;
      case '6h':
        cutoff = now - (6 * 60 * 60 * 1000);
        break;
      case '24h':
        cutoff = now - (24 * 60 * 60 * 1000);
        break;
      case '7d':
        cutoff = now - (7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        cutoff = now - (30 * 24 * 60 * 60 * 1000);
        break;
      default:
        cutoff = 0;
    }

    let filtered = locations.filter(loc => loc.timestamp >= cutoff);

    if (accuracy !== 'all') {
      const maxAccuracy = parseInt(accuracy);
      filtered = filtered.filter(loc => !loc.accuracy || loc.accuracy <= maxAccuracy);
    }

    return filtered.sort((a, b) => b.timestamp - a.timestamp);
  };

  const getMarkerColor = (location: LocationWithDevice, index: number): string => {
    const age = Date.now() - location.timestamp;
    const hours = age / (1000 * 60 * 60);

    if (index === 0) return '#22c55e';
    if (hours < 1) return '#3b82f6';
    if (hours < 6) return '#f59e0b';
    if (hours < 24) return '#ef4444';
    return '#6b7280';
  };

  const createCustomIcon = (color: string, isLatest: boolean = false): L.DivIcon => {
    return L.divIcon({
      className: 'custom-marker',
      html: `
        <div style="
          background-color: ${color};
          width: ${isLatest ? '20px' : '12px'};
          height: ${isLatest ? '20px' : '12px'};
          border-radius: 50%;
          border: 2px solid white;
          box-shadow: 0 2px 4px rgba(0,0,0,0.3);
          ${isLatest ? 'animation: pulse 2s infinite;' : ''}
        "></div>
        <style>
          @keyframes pulse {
            0% { box-shadow: 0 0 0 0 ${color}40; }
            70% { box-shadow: 0 0 0 10px ${color}00; }
            100% { box-shadow: 0 0 0 0 ${color}00; }
          }
        </style>
      `,
      iconSize: [isLatest ? 24 : 16, isLatest ? 24 : 16],
      iconAnchor: [isLatest ? 12 : 8, isLatest ? 12 : 8],
    });
  };

  const exportLocations = () => {
    const csvContent = [
      'Timestamp,Date,Latitude,Longitude,Accuracy,Address',
      ...locations.map(loc => [
        loc.timestamp,
        new Date(loc.timestamp).toISOString(),
        loc.latitude,
        loc.longitude,
        loc.accuracy || 'N/A',
        loc.address || 'N/A'
      ].join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `locations_${device.name}_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  const formatTimestamp = (timestamp: number): string => {
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  const getAccuracyBadge = (accuracy?: number) => {
    if (!accuracy) return <Badge variant="secondary">Unknown</Badge>;

    if (accuracy <= 5) return <Badge variant="default">Excellent</Badge>;
    if (accuracy <= 20) return <Badge variant="default">Good</Badge>;
    if (accuracy <= 50) return <Badge variant="secondary">Fair</Badge>;
    return <Badge variant="destructive">Poor</Badge>;
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center">
              <MapPin className="mr-2 h-5 w-5" />
              Location Tracking
            </CardTitle>
            <CardDescription>
              Real-time location history for {device.name}
            </CardDescription>
          </div>
          <div className="flex items-center space-x-2">
            <Button variant="outline" size="sm" onClick={exportLocations}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button variant="outline" size="sm" onClick={loadLocations}>
              <Refresh className="mr-2 h-4 w-4" />
              Refresh
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent>
        {}
        <div className="flex items-center space-x-4 mb-4 p-3 bg-muted rounded-lg">
          <div className="flex items-center space-x-2">
            <Label htmlFor="time-filter">Time Range:</Label>
            <Select value={timeFilter} onValueChange={setTimeFilter}>
              <SelectTrigger id="time-filter" className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="1h">Last Hour</SelectItem>
                <SelectItem value="6h">Last 6 Hours</SelectItem>
                <SelectItem value="24h">Last 24 Hours</SelectItem>
                <SelectItem value="7d">Last 7 Days</SelectItem>
                <SelectItem value="30d">Last 30 Days</SelectItem>
                <SelectItem value="all">All Time</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center space-x-2">
            <Label htmlFor="accuracy-filter">Accuracy:</Label>
            <Select value={accuracy} onValueChange={setAccuracy}>
              <SelectTrigger id="accuracy-filter" className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="5">High (≤5m)</SelectItem>
                <SelectItem value="20">Good (≤20m)</SelectItem>
                <SelectItem value="50">Fair (≤50m)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center space-x-2">
            <Label htmlFor="show-trail">Show Trail:</Label>
            <Switch
              id="show-trail"
              checked={showTrail}
              onCheckedChange={setShowTrail}
            />
          </div>

          <div className="ml-auto">
            <Badge variant="outline">
              {locations.length} locations
            </Badge>
          </div>
        </div>

        {}
        <div style={{ height, width: '100%' }}>
          {typeof window !== 'undefined' && (
            <MapContainer
              center={center}
              zoom={zoom}
              style={{ height: '100%', width: '100%' }}
              ref={mapRef}
            >
              <TileLayer
                url="https:
                attribution='&copy; <a href="https:
              />

              {}
              {locations.map((location, index) => (
                <Marker
                  key={`${location.timestamp}-${index}`}
                  position={[location.latitude, location.longitude]}
                  icon={createCustomIcon(getMarkerColor(location, index), index === 0)}
                >
                  <Popup>
                    <div className="space-y-2">
                      <div className="font-semibold">{location.deviceName}</div>
                      <div className="text-sm space-y-1">
                        <div>
                          <strong>Time:</strong> {formatTimestamp(location.timestamp)}
                        </div>
                        <div>
                          <strong>Coordinates:</strong> {location.latitude.toFixed(6)}, {location.longitude.toFixed(6)}
                        </div>
                        <div className="flex items-center space-x-2">
                          <strong>Accuracy:</strong>
                          {getAccuracyBadge(location.accuracy)}
                        </div>
                        {location.address && (
                          <div>
                            <strong>Address:</strong> {location.address}
                          </div>
                        )}
                      </div>
                    </div>
                  </Popup>
                </Marker>
              ))}

              {}
              {showTrail && locations.length > 1 && (
                <Polyline
                  positions={locations.map(loc => [loc.latitude, loc.longitude] as [number, number])}
                  color="#3b82f6"
                  weight={3}
                  opacity={0.7}
                />
              )}
            </MapContainer>
          )}
        </div>

        {}
        {locations.length > 0 && (
          <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-primary">
                {locations.length}
              </div>
              <div className="text-sm text-muted-foreground">Total Points</div>
            </div>

            <div className="text-center">
              <div className="text-2xl font-bold text-primary">
                {formatTimestamp(locations[0].timestamp).split(' ')[1]}
              </div>
              <div className="text-sm text-muted-foreground">Latest Update</div>
            </div>

            <div className="text-center">
              <div className="text-2xl font-bold text-primary">
                {locations[0].accuracy ? `${locations[0].accuracy}m` : 'N/A'}
              </div>
              <div className="text-sm text-muted-foreground">Latest Accuracy</div>
            </div>

            <div className="text-center">
              <div className="text-2xl font-bold text-primary">
                {timeFilter === 'all' ? 'All' : timeFilter.toUpperCase()}
              </div>
              <div className="text-sm text-muted-foreground">Time Range</div>
            </div>
          </div>
        )}

        {isLoading && (
          <div className="flex items-center justify-center py-8">
            <div>Loading location data...</div>
          </div>
        )}

        {!isLoading && locations.length === 0 && (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <div className="text-center">
              <MapPin className="mx-auto h-12 w-12 mb-2" />
              <div>No location data found for this device</div>
              <div className="text-sm">Try adjusting the time range or accuracy filters</div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}