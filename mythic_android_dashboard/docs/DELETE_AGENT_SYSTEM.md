# Delete Agent System Documentation

## Overview

The Mythic Android Dashboard implements a secure GUID-based system for managing and deleting agents from target devices. This system ensures that only authorized users can remove agents by requiring exact GUID confirmation.

## How the GUID System Works

### 1. Agent Registration Process

When an APK is built and deployed:

1. **APK Build**: The payload APK is generated with embedded configuration
2. **First Callback**: When the APK is installed and first runs on a device, it calls back to the C2 server
3. **GUID Assignment**: The server assigns a unique GUID (Globally Unique Identifier) to this specific agent/device pair
4. **Dashboard Registration**: The device appears in the dashboard with its assigned GUID

### 2. GUID Structure and Usage

```javascript
// Example GUID format
const deviceGUID = "550e8400-e29b-41d4-a716-446655440000";

// The GUID is used throughout the system for:
// - Device identification
// - API calls
// - WebSocket subscriptions
// - Command routing
```

### 3. Delete Agent Functionality

#### Location: Device Info Tab

The delete agent feature is located in the **"Device Info"** tab of the dashboard:

1. Navigate to any connected device
2. Click on the **"Device Info"** tab
3. Scroll down to the **Device Telemetry** section
4. Click the **"Delete Agent"** button at the bottom

#### Security Confirmation Process

The delete process implements multiple layers of security:

```typescript
// Step 1: User clicks "Delete Agent" button
// Step 2: Confirmation dialog appears
// Step 3: User must type the exact device GUID
// Step 4: Button remains disabled until GUID matches
// Step 5: Final confirmation before deletion
```

#### Implementation Details

```typescript
// State management for delete process
const [confirmationGuid, setConfirmationGuid] = React.useState('');
const [isDeleting, setIsDeleting] = React.useState(false);

// Delete handler with GUID validation
const handleDeleteAgent = async () => {
  // Validate GUID matches exactly
  if (confirmationGuid !== selectedDevice.guid) {
    toast({
      variant: 'destructive',
      title: 'Invalid GUID',
      description: 'The entered GUID does not match the device GUID'
    });
    return;
  }

  setIsDeleting(true);
  try {
    // Call API to delete device
    const response = await apiClient.deleteDevice(selectedDevice.guid);
    
    if (response.success) {
      // Clean up subscriptions
      wsClient.unsubscribeFromDevice(selectedDevice.guid);
      
      // Navigate back to device selection
      onDeviceSelect(null);
      
      // Show success message
      toast({
        title: 'Agent Deleted Successfully',
        description: `Agent with GUID ${selectedDevice.guid} has been uninstalled`
      });
    }
  } catch (error) {
    // Handle errors
  } finally {
    setIsDeleting(false);
  }
};
```

## API Endpoint

### DELETE `/devices/{guid}`

The delete functionality uses a RESTful API endpoint:

```http
DELETE /devices/550e8400-e29b-41d4-a716-446655440000
Authorization: Bearer <auth_token>
Content-Type: application/json
```

**Response:**
```json
{
  "success": true,
  "message": "Device deleted successfully"
}
```

**Error Response:**
```json
{
  "success": false,
  "error": "Device not found or access denied"
}
```

## Frontend Implementation

### UI Components Used

1. **AlertDialog**: For confirmation modal
2. **Input**: For GUID entry with monospace font
3. **Button**: With loading states and disabled logic
4. **Toast Notifications**: For user feedback

### User Experience Flow

```
┌─────────────────┐
│ Click "Delete   │
│ Agent" Button   │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ Confirmation    │
│ Dialog Opens    │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ User Types GUID │
│ (Validation)    │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ Button Enabled  │
│ When GUID Match │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ API Call &      │
│ Loading State   │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐
│ Success/Error   │
│ Toast & Cleanup │
└─────────────────┘
```

## Security Features

### 1. GUID Validation
- Exact string matching required
- Case-sensitive comparison
- No partial matches accepted

### 2. User Confirmation
- Double confirmation process
- Clear warning messages
- Irreversible action warning

### 3. Access Control
- JWT token authentication
- Device ownership validation
- Permission-based access

### 4. Safe Cleanup
- WebSocket unsubscription
- State cleanup
- Navigation reset

## Backend Integration

The delete agent system works with the backend through:

### 1. Device Management
- Device registry maintenance
- GUID-to-device mapping
- Status tracking

### 2. Command Execution
- Uninstall command to device
- Agent self-destruction
- Clean disconnection

### 3. Data Cleanup
- Remove device records
- Clear historical data
- Update campaign assignments

## Error Handling

### Common Error Scenarios

1. **Invalid GUID**
   ```typescript
   // User types wrong GUID
   toast({
     variant: 'destructive',
     title: 'Invalid GUID',
     description: 'The entered GUID does not match the device GUID'
   });
   ```

2. **Network Error**
   ```typescript
   // Connection issues
   toast({
     variant: 'destructive',
     title: 'Connection Error',
     description: 'Failed to communicate with server'
   });
   ```

3. **Device Not Found**
   ```typescript
   // Device already removed or inaccessible
   toast({
     variant: 'destructive',
     title: 'Device Not Found',
     description: 'Device may have already been removed'
   });
   ```

## Testing the System

### Manual Testing Steps

1. **Setup Test Device**
   - Build and deploy test APK
   - Verify device appears in dashboard
   - Note the assigned GUID

2. **Test Delete Process**
   - Navigate to Device Info tab
   - Click Delete Agent button
   - Try wrong GUID (should fail)
   - Enter correct GUID
   - Verify successful deletion

3. **Verify Cleanup**
   - Check device no longer appears in sidebar
   - Verify no active WebSocket connections
   - Confirm backend data removal

### Automated Testing

```typescript
// Example test case
describe('Delete Agent System', () => {
  it('should require exact GUID match', async () => {
    const wrongGuid = 'wrong-guid';
    const correctGuid = 'correct-guid';
    
    // Test wrong GUID
    expect(handleDeleteAgent(wrongGuid)).rejects.toThrow();
    
    // Test correct GUID
    expect(handleDeleteAgent(correctGuid)).resolves.toBeTruthy();
  });
});
```

## Troubleshooting

### Common Issues

1. **GUID Not Visible**
   - Check dashboard header (GUID displayed)
   - Verify device is properly connected
   - Refresh browser if needed

2. **Delete Button Disabled**
   - Ensure GUID is typed exactly (copy/paste recommended)
   - Check for extra spaces or characters
   - Verify case sensitivity

3. **Delete Fails**
   - Check network connectivity
   - Verify authentication token
   - Review server logs for errors

### Debugging Tips

1. **Browser Console**
   ```javascript
   // Check current device GUID
   console.log(selectedDevice.guid);
   
   // Monitor API calls
   console.log('Delete request:', response);
   ```

2. **Network Tab**
   - Monitor DELETE request to `/devices/{guid}`
   - Check response status and body
   - Verify authentication headers

## Best Practices

### For Users
1. **Copy/Paste GUID**: Avoid typing errors by copy/pasting the GUID from the header
2. **Double-Check**: Verify you're deleting the correct device
3. **Backup Data**: Download important data before deletion

### For Developers
1. **Input Validation**: Always validate GUID format and existence
2. **Error Handling**: Provide clear error messages
3. **Loading States**: Show progress during deletion
4. **Cleanup**: Ensure proper resource cleanup after deletion

## Future Enhancements

### Planned Features
1. **Bulk Delete**: Select multiple devices for deletion
2. **Soft Delete**: Temporarily disable instead of permanent removal
3. **Delete History**: Log of deleted devices for audit
4. **Batch Operations**: Execute multiple device commands
5. **Confirmation Alternatives**: QR code or 2FA confirmation

### Configuration Options
```typescript
interface DeleteConfig {
  requireGuidConfirmation: boolean;
  enableSoftDelete: boolean;
  retentionPeriod: number; // days
  auditLogging: boolean;
}
```

This comprehensive system ensures secure, reliable agent management while providing a clear user experience and robust error handling.
