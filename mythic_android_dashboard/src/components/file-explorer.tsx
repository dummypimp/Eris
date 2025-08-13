'use client';

import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useToast } from '@/hooks/use-toast';
import { apiClient } from '@/lib/api-client';
import { FileSystemItem, Device } from '@/lib/types';
import {
  Folder,
  File,
  Image,
  Music,
  Video,
  FileText,
  Download,
  Eye,
  MoreVertical,
  ArrowLeft,
  Home,
  Search,
  Filter,
  SortAsc,
  SortDesc,
  Grid3X3,
  List,
} from 'lucide-react';
import { formatDistance } from 'date-fns';

interface FileExplorerProps {
  device: Device;
}

type ViewMode = 'list' | 'grid';
type SortField = 'name' | 'size' | 'modified' | 'type';
type SortDirection = 'asc' | 'desc';

export function FileExplorer({ device }: FileExplorerProps) {
  const [files, setFiles] = useState<FileSystemItem[]>([]);
  const [currentPath, setCurrentPath] = useState('/sdcard');
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState<ViewMode>('list');
  const [sortField, setSortField] = useState<SortField>('name');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');
  const [selectedFile, setSelectedFile] = useState<FileSystemItem | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [pathHistory, setPathHistory] = useState<string[]>([]);
  const { toast } = useToast();

  useEffect(() => {
    loadFiles(currentPath);
  }, [device, currentPath]);

  const loadFiles = async (path: string) => {
    setIsLoading(true);
    try {
      const response = await apiClient.getFiles(device.guid, path);
      if (response.success && response.data) {
        setFiles(response.data);
      } else {
        toast({
          variant: 'destructive',
          title: 'Error',
          description: response.error || 'Failed to load files',
        });
      }
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Failed to load files',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const navigateToPath = (path: string) => {
    if (path !== currentPath) {
      setPathHistory([...pathHistory, currentPath]);
      setCurrentPath(path);
    }
  };

  const navigateBack = () => {
    if (pathHistory.length > 0) {
      const previousPath = pathHistory[pathHistory.length - 1];
      setPathHistory(pathHistory.slice(0, -1));
      setCurrentPath(previousPath);
    }
  };

  const navigateHome = () => {
    setPathHistory([]);
    setCurrentPath('/sdcard');
  };

  const handleFileClick = (file: FileSystemItem) => {
    if (file.type === 'directory') {
      navigateToPath(file.path);
    } else {
      setSelectedFile(file);
      setShowPreview(true);
    }
  };

  const downloadFile = async (file: FileSystemItem) => {
    try {
      const response = await apiClient.downloadFile(device.guid, file.path);
      if (response.success && response.data) {
        window.open(response.data.downloadUrl, '_blank');
        toast({
          title: 'Success',
          description: 'File download started',
        });
      } else {
        toast({
          variant: 'destructive',
          title: 'Error',
          description: response.error || 'Failed to download file',
        });
      }
    } catch (error) {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Failed to download file',
      });
    }
  };

  const getFileIcon = (file: FileSystemItem) => {
    if (file.type === 'directory') {
      return <Folder className="h-5 w-5 text-blue-500" />;
    }

    const extension = file.name.split('.').pop()?.toLowerCase();

    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'].includes(extension || '')) {
      return <Image className="h-5 w-5 text-green-500" />;
    }

    if (['mp3', 'wav', 'flac', 'aac', 'ogg'].includes(extension || '')) {
      return <Music className="h-5 w-5 text-purple-500" />;
    }

    if (['mp4', 'avi', 'mkv', 'mov', 'webm'].includes(extension || '')) {
      return <Video className="h-5 w-5 text-red-500" />;
    }

    if (['txt', 'md', 'log', 'json', 'xml'].includes(extension || '')) {
      return <FileText className="h-5 w-5 text-yellow-500" />;
    }

    return <File className="h-5 w-5 text-gray-500" />;
  };

  const formatFileSize = (bytes?: number) => {
    if (!bytes) return 'N/A';

    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const filteredAndSortedFiles = files
    .filter(file =>
      file.name.toLowerCase().includes(searchQuery.toLowerCase())
    )
    .sort((a, b) => {
      let aValue: any, bValue: any;

      switch (sortField) {
        case 'name':
          aValue = a.name.toLowerCase();
          bValue = b.name.toLowerCase();
          break;
        case 'size':
          aValue = a.size || 0;
          bValue = b.size || 0;
          break;
        case 'modified':
          aValue = new Date(a.modified).getTime();
          bValue = new Date(b.modified).getTime();
          break;
        case 'type':
          aValue = a.type;
          bValue = b.type;
          break;
        default:
          return 0;
      }

      if (sortDirection === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  const getBreadcrumbs = () => {
    const parts = currentPath.split('/').filter(Boolean);
    return ['', ...parts];
  };

  const FilePreview = ({ file }: { file: FileSystemItem }) => {
    const extension = file.name.split('.').pop()?.toLowerCase();

    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'].includes(extension || '')) {
      return (
        <div className="flex justify-center">
          <img
            src={`/api/files/preview/${device.guid}?path=${encodeURIComponent(file.path)}`}
            alt={file.name}
            className="max-w-full max-h-96 object-contain"
            onError={(e) => {
              (e.target as HTMLImageElement).src = '/placeholder-image.png';
            }}
          />
        </div>
      );
    }

    if (['txt', 'md', 'log', 'json', 'xml'].includes(extension || '')) {
      return (
        <div className="bg-muted p-4 rounded-lg">
          <pre className="text-sm whitespace-pre-wrap max-h-96 overflow-auto">
            Text preview would be loaded here...
          </pre>
        </div>
      );
    }

    return (
      <div className="text-center text-muted-foreground py-8">
        <File className="mx-auto h-16 w-16 mb-4" />
        <p>Preview not available for this file type</p>
        <p className="text-sm">Use the download button to save the file</p>
      </div>
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center">
            <Folder className="mr-2 h-5 w-5" />
            File Explorer
          </div>
          <div className="flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setViewMode(viewMode === 'list' ? 'grid' : 'list')}
            >
              {viewMode === 'list' ? <Grid3X3 className="h-4 w-4" /> : <List className="h-4 w-4" />}
            </Button>
            <Button variant="outline" size="sm" onClick={navigateHome}>
              <Home className="h-4 w-4" />
            </Button>
            {pathHistory.length > 0 && (
              <Button variant="outline" size="sm" onClick={navigateBack}>
                <ArrowLeft className="h-4 w-4" />
              </Button>
            )}
          </div>
        </CardTitle>
        <CardDescription>
          Browse and manage files on {device.name}
        </CardDescription>

        {}
        <div className="flex items-center space-x-2 text-sm">
          {getBreadcrumbs().map((part, index) => (
            <React.Fragment key={index}>
              {index > 0 && <span className="text-muted-foreground">/</span>}
              <button
                className="text-blue-500 hover:underline"
                onClick={() => {
                  if (index === 0) {
                    navigateHome();
                  } else {
                    const path = '/' + getBreadcrumbs().slice(1, index + 1).join('/');
                    navigateToPath(path);
                  }
                }}
              >
                {part === '' ? 'root' : part}
              </button>
            </React.Fragment>
          ))}
        </div>

        {}
        <div className="flex items-center space-x-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search files..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9"
            />
          </div>
          <Badge variant="outline">
            {filteredAndSortedFiles.length} items
          </Badge>
        </div>
      </CardHeader>

      <CardContent>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <div>Loading files...</div>
          </div>
        ) : (
          <div className="space-y-4">
            {}
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12"></TableHead>
                  <TableHead
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => toggleSort('name')}
                  >
                    <div className="flex items-center">
                      Name
                      {sortField === 'name' && (
                        sortDirection === 'asc' ? <SortAsc className="ml-2 h-4 w-4" /> : <SortDesc className="ml-2 h-4 w-4" />
                      )}
                    </div>
                  </TableHead>
                  <TableHead
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => toggleSort('size')}
                  >
                    <div className="flex items-center">
                      Size
                      {sortField === 'size' && (
                        sortDirection === 'asc' ? <SortAsc className="ml-2 h-4 w-4" /> : <SortDesc className="ml-2 h-4 w-4" />
                      )}
                    </div>
                  </TableHead>
                  <TableHead
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => toggleSort('modified')}
                  >
                    <div className="flex items-center">
                      Modified
                      {sortField === 'modified' && (
                        sortDirection === 'asc' ? <SortAsc className="ml-2 h-4 w-4" /> : <SortDesc className="ml-2 h-4 w-4" />
                      )}
                    </div>
                  </TableHead>
                  <TableHead>Permissions</TableHead>
                  <TableHead className="w-12"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAndSortedFiles.map((file) => (
                  <TableRow
                    key={file.path}
                    className="cursor-pointer hover:bg-muted/50"
                  >
                    <TableCell onClick={() => handleFileClick(file)}>
                      {getFileIcon(file)}
                    </TableCell>
                    <TableCell onClick={() => handleFileClick(file)}>
                      <div className="flex items-center space-x-2">
                        <span className={file.isHidden ? 'opacity-50' : ''}>
                          {file.name}
                        </span>
                        {file.isHidden && <Badge variant="secondary" className="text-xs">Hidden</Badge>}
                      </div>
                    </TableCell>
                    <TableCell onClick={() => handleFileClick(file)}>
                      {file.type === 'directory' ? '-' : formatFileSize(file.size)}
                    </TableCell>
                    <TableCell onClick={() => handleFileClick(file)}>
                      {formatDistance(new Date(file.modified), new Date(), { addSuffix: true })}
                    </TableCell>
                    <TableCell onClick={() => handleFileClick(file)}>
                      <code className="text-xs">{file.permissions || 'N/A'}</code>
                    </TableCell>
                    <TableCell>
                      {file.type === 'file' && (
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm">
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent>
                            <DropdownMenuItem onClick={() => handleFileClick(file)}>
                              <Eye className="mr-2 h-4 w-4" />
                              Preview
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => downloadFile(file)}>
                              <Download className="mr-2 h-4 w-4" />
                              Download
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>

            {filteredAndSortedFiles.length === 0 && !isLoading && (
              <div className="text-center py-8 text-muted-foreground">
                <Folder className="mx-auto h-12 w-12 mb-4" />
                <p>No files found</p>
                {searchQuery && (
                  <p className="text-sm">Try adjusting your search query</p>
                )}
              </div>
            )}
          </div>
        )}
      </CardContent>

      {}
      <Dialog open={showPreview} onOpenChange={setShowPreview}>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle className="flex items-center justify-between">
              <div className="flex items-center">
                {selectedFile && getFileIcon(selectedFile)}
                <span className="ml-2">{selectedFile?.name}</span>
              </div>
              <div className="flex items-center space-x-2">
                {selectedFile && (
                  <Button variant="outline" onClick={() => downloadFile(selectedFile)}>
                    <Download className="mr-2 h-4 w-4" />
                    Download
                  </Button>
                )}
              </div>
            </DialogTitle>
            <DialogDescription>
              {selectedFile && (
                <div className="flex items-center space-x-4 text-sm">
                  <span>Size: {formatFileSize(selectedFile.size)}</span>
                  <span>Modified: {formatDistance(new Date(selectedFile.modified), new Date(), { addSuffix: true })}</span>
                  {selectedFile.permissions && <span>Permissions: {selectedFile.permissions}</span>}
                </div>
              )}
            </DialogDescription>
          </DialogHeader>

          <div className="max-h-96 overflow-auto">
            {selectedFile && <FilePreview file={selectedFile} />}
          </div>
        </DialogContent>
      </Dialog>
    </Card>
  );
}