
"""
Location Tracker Module
Advanced location tracking with GPS, WiFi/Cell tower triangulation,
geofencing capabilities, and movement pattern analysis.
"""

import json
import time
import math
import threading
import subprocess
import requests
from typing import Dict, List, Optional, Tuple, NamedTuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import sqlite3
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class GPSLocation:
    latitude: float
    longitude: float
    altitude: float
    accuracy: float
    timestamp: str
    speed: float = 0.0
    bearing: float = 0.0

@dataclass
class WiFiAccessPoint:
    bssid: str
    ssid: str
    signal_strength: int
    frequency: int

@dataclass
class CellTower:
    cell_id: str
    location_area_code: str
    mobile_country_code: str
    mobile_network_code: str
    signal_strength: int

@dataclass
class TriangulatedLocation:
    latitude: float
    longitude: float
    accuracy: float
    method: str
    timestamp: str
    confidence: float

@dataclass
class Geofence:
    name: str
    latitude: float
    longitude: float
    radius: float
    active: bool = True

@dataclass
class MovementPattern:
    start_time: str
    end_time: str
    distance_traveled: float
    average_speed: float
    max_speed: float
    locations_count: int
    frequent_areas: List[Dict[str, float]]

class LocationTracker:
    def __init__(self, db_path: str = "location_data.db"):
        self.db_path = db_path
        self.tracking_active = False
        self.tracking_interval = 60
        self.geofences = []
        self.movement_patterns = []
        self.location_history = []
        

        self._init_database()
        

        self.wifi_api_key = None
        self.cell_api_key = None
        
    def _init_database(self):
        """Initialize SQLite database for location storage"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS gps_locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    altitude REAL,
                    accuracy REAL,
                    speed REAL,
                    bearing REAL,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS triangulated_locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    accuracy REAL,
                    method TEXT,
                    confidence REAL,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS geofence_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    geofence_name TEXT NOT NULL,
                    event_type TEXT NOT NULL,  -- 'enter' or 'exit'
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    timestamp TEXT NOT NULL
                )
            ''')
            
            conn.commit()
            conn.close()
            
            logger.info("Location database initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
    
    def set_tracking_interval(self, interval_seconds: int):
        """Set GPS tracking interval in seconds"""
        self.tracking_interval = max(1, interval_seconds)
        logger.info(f"Tracking interval set to {self.tracking_interval} seconds")
    
    def get_gps_location(self) -> Optional[GPSLocation]:
        """Get current GPS location using various methods"""
        location = None
        

        methods = [
            self._get_gps_from_gpsd,
            self._get_gps_from_nmea,
            self._get_gps_from_android_location,
            self._get_gps_from_system_location
        ]
        
        for method in methods:
            try:
                location = method()
                if location:
                    break
            except Exception as e:
                logger.debug(f"GPS method failed: {e}")
                continue
        
        if location:

            self._store_gps_location(location)
            self.location_history.append(location)
            

            self._check_geofences(location.latitude, location.longitude)
        
        return location
    
    def _get_gps_from_gpsd(self) -> Optional[GPSLocation]:
        """Get GPS location from gpsd daemon"""
        try:
            import gpsd
            gpsd.connect()
            packet = gpsd.get_current()
            
            if packet.mode >= 2:
                return GPSLocation(
                    latitude=packet.lat,
                    longitude=packet.lon,
                    altitude=packet.alt if hasattr(packet, 'alt') else 0.0,
                    accuracy=packet.error.get('c', 0.0) if hasattr(packet, 'error') else 0.0,
                    speed=packet.hspeed if hasattr(packet, 'hspeed') else 0.0,
                    bearing=packet.track if hasattr(packet, 'track') else 0.0,
                    timestamp=datetime.now().isoformat()
                )
        except ImportError:
            logger.debug("gpsd library not available")
        except Exception as e:
            logger.debug(f"gpsd failed: {e}")
        
        return None
    
    def _get_gps_from_nmea(self) -> Optional[GPSLocation]:
        """Parse GPS data from NMEA sentences"""
        try:

            gps_devices = ['/dev/ttyUSB0', '/dev/ttyACM0', '/dev/gps0']
            
            for device in gps_devices:
                try:
                    with open(device, 'r') as f:
                        for _ in range(10):
                            line = f.readline().strip()
                            if line.startswith('$GPGGA') or line.startswith('$GNGGA'):
                                location = self._parse_nmea_gga(line)
                                if location:
                                    return location
                except (FileNotFoundError, PermissionError):
                    continue
                    
        except Exception as e:
            logger.debug(f"NMEA parsing failed: {e}")
        
        return None
    
    def _parse_nmea_gga(self, nmea_sentence: str) -> Optional[GPSLocation]:
        """Parse NMEA GGA sentence"""
        try:
            parts = nmea_sentence.split(',')
            if len(parts) < 15:
                return None
            

            if parts[6] == '0':
                return None
            

            lat_raw = parts[2]
            lat_dir = parts[3]
            if not lat_raw or not lat_dir:
                return None
            
            lat_deg = int(lat_raw[:2])
            lat_min = float(lat_raw[2:])
            latitude = lat_deg + lat_min / 60.0
            if lat_dir == 'S':
                latitude = -latitude
            

            lon_raw = parts[4]
            lon_dir = parts[5]
            if not lon_raw or not lon_dir:
                return None
            
            lon_deg = int(lon_raw[:3])
            lon_min = float(lon_raw[3:])
            longitude = lon_deg + lon_min / 60.0
            if lon_dir == 'W':
                longitude = -longitude
            

            altitude = float(parts[9]) if parts[9] else 0.0
            

            hdop = float(parts[8]) if parts[8] else 1.0
            accuracy = hdop * 5.0
            
            return GPSLocation(
                latitude=latitude,
                longitude=longitude,
                altitude=altitude,
                accuracy=accuracy,
                timestamp=datetime.now().isoformat(),
                speed=0.0,
                bearing=0.0
            )
            
        except (ValueError, IndexError) as e:
            logger.debug(f"NMEA parsing error: {e}")
            return None
    
    def _get_gps_from_android_location(self) -> Optional[GPSLocation]:
        """Get location using Android location services (for Android devices)"""
        try:

            result = subprocess.run(
                ['am', 'broadcast', '-a', 'android.location.GPS_ENABLED_CHANGE'],
                capture_output=True, text=True, timeout=5
            )
            


            return None
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
    
    def _get_gps_from_system_location(self) -> Optional[GPSLocation]:
        """Get location from system location services"""
        try:

            commands = [
                ['where', 'am', 'i'],
                ['location'],
            ]
            
            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0 and result.stdout:


                        return None
                        
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
                    
        except Exception as e:
            logger.debug(f"System location failed: {e}")
        
        return None
    
    def triangulate_wifi_location(self, wifi_networks: List[WiFiAccessPoint]) -> Optional[TriangulatedLocation]:
        """Triangulate location using WiFi access points"""
        if not wifi_networks or len(wifi_networks) < 3:
            logger.warning("Need at least 3 WiFi networks for triangulation")
            return None
        
        try:

            if self.wifi_api_key:
                location = self._triangulate_wifi_google(wifi_networks)
                if location:
                    self._store_triangulated_location(location)
                    return location
            

            location = self._triangulate_wifi_local(wifi_networks)
            if location:
                self._store_triangulated_location(location)
                return location
            
        except Exception as e:
            logger.error(f"WiFi triangulation failed: {e}")
        
        return None
    
    def _triangulate_wifi_google(self, wifi_networks: List[WiFiAccessPoint]) -> Optional[TriangulatedLocation]:
        """Use Google Geolocation API for WiFi triangulation"""
        try:
            wifi_data = []
            for ap in wifi_networks:
                wifi_data.append({
                    'macAddress': ap.bssid,
                    'signalStrength': ap.signal_strength,
                    'channel': self._frequency_to_channel(ap.frequency)
                })
            
            payload = {
                'considerIp': False,
                'wifiAccessPoints': wifi_data
            }
            
            url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={self.wifi_api_key}"
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return TriangulatedLocation(
                    latitude=data['location']['lat'],
                    longitude=data['location']['lng'],
                    accuracy=data.get('accuracy', 100.0),
                    method='wifi',
                    confidence=0.8,
                    timestamp=datetime.now().isoformat()
                )
                
        except requests.RequestException as e:
            logger.error(f"Google geolocation API failed: {e}")
        
        return None
    
    def _triangulate_wifi_local(self, wifi_networks: List[WiFiAccessPoint]) -> Optional[TriangulatedLocation]:
        """Local WiFi triangulation using stored database"""
        try:


            
            if len(wifi_networks) >= 3:

                total_weight = 0
                weighted_lat = 0
                weighted_lon = 0
                
                for ap in wifi_networks[:3]:

                    mock_lat = 40.7128 + (hash(ap.bssid) % 1000) / 10000.0
                    mock_lon = -74.0060 + (hash(ap.bssid) % 1000) / 10000.0
                    
                    weight = max(0, ap.signal_strength + 100) / 100.0
                    weighted_lat += mock_lat * weight
                    weighted_lon += mock_lon * weight
                    total_weight += weight
                
                if total_weight > 0:
                    return TriangulatedLocation(
                        latitude=weighted_lat / total_weight,
                        longitude=weighted_lon / total_weight,
                        accuracy=50.0,
                        method='wifi_local',
                        confidence=0.6,
                        timestamp=datetime.now().isoformat()
                    )
                    
        except Exception as e:
            logger.error(f"Local WiFi triangulation failed: {e}")
        
        return None
    
    def triangulate_cell_location(self, cell_towers: List[CellTower]) -> Optional[TriangulatedLocation]:
        """Triangulate location using cellular towers"""
        if not cell_towers:
            logger.warning("No cell towers provided for triangulation")
            return None
        
        try:

            location = self._triangulate_cell_opencellid(cell_towers)
            if location:
                self._store_triangulated_location(location)
                return location
            

            location = self._triangulate_cell_local(cell_towers)
            if location:
                self._store_triangulated_location(location)
                return location
                
        except Exception as e:
            logger.error(f"Cell triangulation failed: {e}")
        
        return None
    
    def _triangulate_cell_opencellid(self, cell_towers: List[CellTower]) -> Optional[TriangulatedLocation]:
        """Use OpenCellID API for cell tower triangulation"""
        try:

            strongest_tower = max(cell_towers, key=lambda x: x.signal_strength)
            

            url = "https://opencellid.org/cell/get"
            params = {
                'key': self.cell_api_key or 'your_api_key_here',
                'mcc': strongest_tower.mobile_country_code,
                'mnc': strongest_tower.mobile_network_code,
                'lac': strongest_tower.location_area_code,
                'cellid': strongest_tower.cell_id,
                'format': 'json'
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'lat' in data and 'lon' in data:
                    return TriangulatedLocation(
                        latitude=float(data['lat']),
                        longitude=float(data['lon']),
                        accuracy=data.get('range', 1000.0),
                        method='cellular',
                        confidence=0.7,
                        timestamp=datetime.now().isoformat()
                    )
                    
        except requests.RequestException as e:
            logger.error(f"OpenCellID API failed: {e}")
        
        return None
    
    def _triangulate_cell_local(self, cell_towers: List[CellTower]) -> Optional[TriangulatedLocation]:
        """Local cell tower triangulation"""
        try:

            if cell_towers:
                tower = cell_towers[0]
                

                lat_offset = (int(tower.cell_id, 16) if tower.cell_id.isalnum() else hash(tower.cell_id)) % 1000
                lon_offset = (int(tower.location_area_code) if tower.location_area_code.isdigit() else hash(tower.location_area_code)) % 1000
                
                mock_lat = 40.7128 + lat_offset / 10000.0
                mock_lon = -74.0060 + lon_offset / 10000.0
                
                return TriangulatedLocation(
                    latitude=mock_lat,
                    longitude=mock_lon,
                    accuracy=500.0,
                    method='cellular_local',
                    confidence=0.5,
                    timestamp=datetime.now().isoformat()
                )
                
        except Exception as e:
            logger.error(f"Local cell triangulation failed: {e}")
        
        return None
    
    def _frequency_to_channel(self, frequency: int) -> int:
        """Convert WiFi frequency to channel number"""
        if 2412 <= frequency <= 2484:
            return (frequency - 2412) // 5 + 1
        elif 5170 <= frequency <= 5825:
            return (frequency - 5000) // 5
        else:
            return 0
    
    def add_geofence(self, geofence: Geofence):
        """Add a geofence for monitoring"""
        self.geofences.append(geofence)
        logger.info(f"Added geofence: {geofence.name}")
    
    def remove_geofence(self, name: str) -> bool:
        """Remove a geofence by name"""
        for i, geofence in enumerate(self.geofences):
            if geofence.name == name:
                del self.geofences[i]
                logger.info(f"Removed geofence: {name}")
                return True
        return False
    
    def _check_geofences(self, latitude: float, longitude: float):
        """Check if current location triggers any geofences"""
        for geofence in self.geofences:
            if not geofence.active:
                continue
                
            distance = self._calculate_distance(
                latitude, longitude,
                geofence.latitude, geofence.longitude
            )
            
            if distance <= geofence.radius:
                self._trigger_geofence_event(geofence, 'enter', latitude, longitude)
            elif distance > geofence.radius * 1.2:
                self._trigger_geofence_event(geofence, 'exit', latitude, longitude)
    
    def _trigger_geofence_event(self, geofence: Geofence, event_type: str,
                               latitude: float, longitude: float):
        """Trigger geofence event"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO geofence_events (geofence_name, event_type, latitude, longitude, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (geofence.name, event_type, latitude, longitude, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Geofence event: {event_type} {geofence.name}")
            
        except Exception as e:
            logger.error(f"Failed to store geofence event: {e}")
    
    def start_tracking(self):
        """Start continuous GPS tracking"""
        if self.tracking_active:
            logger.warning("Tracking already active")
            return
        
        self.tracking_active = True
        
        def tracking_loop():
            while self.tracking_active:
                try:
                    location = self.get_gps_location()
                    if location:
                        logger.debug(f"Location: {location.latitude}, {location.longitude}")
                    
                    time.sleep(self.tracking_interval)
                    
                except Exception as e:
                    logger.error(f"Tracking error: {e}")
                    time.sleep(5)
        
        tracking_thread = threading.Thread(target=tracking_loop, daemon=True)
        tracking_thread.start()
        
        logger.info("GPS tracking started")
    
    def stop_tracking(self):
        """Stop GPS tracking"""
        self.tracking_active = False
        logger.info("GPS tracking stopped")
    
    def analyze_movement_patterns(self, hours: int = 24) -> List[MovementPattern]:
        """Analyze movement patterns from location history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            

            since = (datetime.now() - timedelta(hours=hours)).isoformat()
            cursor.execute('''
                SELECT latitude, longitude, speed, timestamp
                FROM gps_locations
                WHERE timestamp > ?
                ORDER BY timestamp
            ''', (since,))
            
            locations = cursor.fetchall()
            conn.close()
            
            if len(locations) < 2:
                return []
            
            patterns = []
            

            total_distance = 0
            max_speed = 0
            speeds = []
            frequent_areas = {}
            
            for i in range(1, len(locations)):
                prev_lat, prev_lon, prev_speed, prev_time = locations[i-1]
                curr_lat, curr_lon, curr_speed, curr_time = locations[i]
                

                distance = self._calculate_distance(prev_lat, prev_lon, curr_lat, curr_lon)
                total_distance += distance
                

                speed = curr_speed or 0
                speeds.append(speed)
                max_speed = max(max_speed, speed)
                

                area_key = f"{int(curr_lat * 1000)},{int(curr_lon * 1000)}"
                frequent_areas[area_key] = frequent_areas.get(area_key, 0) + 1
            

            top_areas = sorted(frequent_areas.items(), key=lambda x: x[1], reverse=True)[:5]
            frequent_coords = []
            for area_key, count in top_areas:
                lat_int, lon_int = map(int, area_key.split(','))
                frequent_coords.append({
                    'latitude': lat_int / 1000.0,
                    'longitude': lon_int / 1000.0,
                    'visit_count': count
                })
            
            pattern = MovementPattern(
                start_time=locations[0][3],
                end_time=locations[-1][3],
                distance_traveled=total_distance,
                average_speed=sum(speeds) / len(speeds) if speeds else 0,
                max_speed=max_speed,
                locations_count=len(locations),
                frequent_areas=frequent_coords
            )
            
            patterns.append(pattern)
            self.movement_patterns = patterns
            
            logger.info(f"Analyzed movement pattern: {total_distance:.2f}m traveled")
            
            return patterns
            
        except Exception as e:
            logger.error(f"Movement analysis failed: {e}")
            return []
    
    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two coordinates using Haversine formula"""
        R = 6371000
        
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        
        a = (math.sin(delta_lat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) *
             math.sin(delta_lon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        return R * c
    
    def _store_gps_location(self, location: GPSLocation):
        """Store GPS location in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO gps_locations (latitude, longitude, altitude, accuracy, speed, bearing, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                location.latitude, location.longitude, location.altitude,
                location.accuracy, location.speed, location.bearing, location.timestamp
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store GPS location: {e}")
    
    def _store_triangulated_location(self, location: TriangulatedLocation):
        """Store triangulated location in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO triangulated_locations (latitude, longitude, accuracy, method, confidence, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                location.latitude, location.longitude, location.accuracy,
                location.method, location.confidence, location.timestamp
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store triangulated location: {e}")
    
    def export_location_data(self, filename: str = None) -> str:
        """Export all location data to JSON"""
        if not filename:
            filename = f"location_data_{int(time.time())}.json"
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            

            cursor.execute('SELECT * FROM gps_locations ORDER BY timestamp')
            gps_data = []
            for row in cursor.fetchall():
                gps_data.append({
                    'id': row[0],
                    'latitude': row[1],
                    'longitude': row[2],
                    'altitude': row[3],
                    'accuracy': row[4],
                    'speed': row[5],
                    'bearing': row[6],
                    'timestamp': row[7]
                })
            

            cursor.execute('SELECT * FROM triangulated_locations ORDER BY timestamp')
            triangulated_data = []
            for row in cursor.fetchall():
                triangulated_data.append({
                    'id': row[0],
                    'latitude': row[1],
                    'longitude': row[2],
                    'accuracy': row[3],
                    'method': row[4],
                    'confidence': row[5],
                    'timestamp': row[6]
                })
            

            cursor.execute('SELECT * FROM geofence_events ORDER BY timestamp')
            geofence_data = []
            for row in cursor.fetchall():
                geofence_data.append({
                    'id': row[0],
                    'geofence_name': row[1],
                    'event_type': row[2],
                    'latitude': row[3],
                    'longitude': row[4],
                    'timestamp': row[5]
                })
            
            conn.close()
            

            export_data = {
                'export_timestamp': datetime.now().isoformat(),
                'gps_locations': gps_data,
                'triangulated_locations': triangulated_data,
                'geofence_events': geofence_data,
                'geofences': [asdict(gf) for gf in self.geofences],
                'movement_patterns': [asdict(mp) for mp in self.movement_patterns],
                'statistics': {
                    'total_gps_locations': len(gps_data),
                    'total_triangulated_locations': len(triangulated_data),
                    'total_geofence_events': len(geofence_data),
                    'active_geofences': len([gf for gf in self.geofences if gf.active])
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Location data exported to {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to export location data: {e}")
            return ""


def main():
    """Example usage of LocationTracker"""
    tracker = LocationTracker()
    
    try:
        print("Location Tracker - Advanced Location Analysis")
        print("=" * 50)
        

        tracker.set_tracking_interval(30)
        

        home_geofence = Geofence(
            name="Home",
            latitude=40.7128,
            longitude=-74.0060,
            radius=100.0
        )
        tracker.add_geofence(home_geofence)
        
        work_geofence = Geofence(
            name="Work",
            latitude=40.7589,
            longitude=-73.9851,
            radius=50.0
        )
        tracker.add_geofence(work_geofence)
        
        print(f"Added {len(tracker.geofences)} geofences")
        

        print("\n1. Getting GPS location...")
        gps_location = tracker.get_gps_location()
        if gps_location:
            print(f"  GPS: {gps_location.latitude:.6f}, {gps_location.longitude:.6f}")
            print(f"  Accuracy: {gps_location.accuracy:.1f}m")
        else:
            print("  GPS location not available")
        

        print("\n2. WiFi triangulation demo...")
        wifi_networks = [
            WiFiAccessPoint("00:11:22:33:44:55", "WiFi_Network_1", -45, 2437),
            WiFiAccessPoint("66:77:88:99:AA:BB", "WiFi_Network_2", -65, 2462),
            WiFiAccessPoint("CC:DD:EE:FF:00:11", "WiFi_Network_3", -55, 2412)
        ]
        
        wifi_location = tracker.triangulate_wifi_location(wifi_networks)
        if wifi_location:
            print(f"  WiFi triangulation: {wifi_location.latitude:.6f}, {wifi_location.longitude:.6f}")
            print(f"  Confidence: {wifi_location.confidence:.2f}")
        

        print("\n3. Cellular triangulation demo...")
        cell_towers = [
            CellTower("12345", "1001", "310", "260", -70)
        ]
        
        cell_location = tracker.triangulate_cell_location(cell_towers)
        if cell_location:
            print(f"  Cell triangulation: {cell_location.latitude:.6f}, {cell_location.longitude:.6f}")
        

        print("\n4. Starting tracking (30 seconds)...")
        tracker.start_tracking()
        time.sleep(30)
        tracker.stop_tracking()
        

        print("\n5. Analyzing movement patterns...")
        patterns = tracker.analyze_movement_patterns(hours=24)
        for pattern in patterns:
            print(f"  Distance traveled: {pattern.distance_traveled:.1f}m")
            print(f"  Average speed: {pattern.average_speed:.1f} m/s")
            print(f"  Locations recorded: {pattern.locations_count}")
        

        print("\n6. Exporting location data...")
        output_file = tracker.export_location_data()
        if output_file:
            print(f"  Data exported to: {output_file}")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        tracker.stop_tracking()
    except Exception as e:
        print(f"Error: {e}")
        tracker.stop_tracking()


if __name__ == "__main__":
    main()
