# Mythic-Inspired C2 Dashboard - Design & Architecture

This document outlines the design, architecture, and expansion guide for the web-based C2 dashboard interface. The application is built with a modern tech stack and designed to be modular, scalable, and easily connectable to a live C2 backend.

## 1. Core Design Philosophy

The UI/UX is heavily inspired by modern C2 frameworks, prioritizing information density, clarity, and operator efficiency. The aesthetic choices aim for a professional, dark-themed environment that is both functional and visually appealing.

### Color Palette

The color scheme is central to the UI's identity, providing visual cues for status, actions, and alerts.

| Purpose                  | Color Name      | Hex Code  | Recommended Usage                                           |
| ------------------------ | --------------- | --------- | ----------------------------------------------------------- |
| **Primary Background**   | Dark Charcoal   | `#2c2d34` | Main background for the app, providing a neutral dark canvas. |
| **Primary Accent/Error** | Burnt Orange    | `#e94822` | Used for critical actions like "Delete", errors, and alerts.    |
| **Secondary Accent**     | Bright Orange   | `#f2910a` | Used for warnings, notifications, and secondary highlights.     |
| **Highlight/Info**       | Golden Yellow   | `#efd510` | Used for informational banners, success states, or active items. |

## 2. Technical Architecture

The application is built on a robust and modern tech stack, chosen for its performance, developer experience, and scalability.

**Tech Stack:**

*   **Framework:** Next.js (with App Router)
*   **Language:** TypeScript
*   **UI Library:** React
*   **Styling:** Tailwind CSS
*   **Component Library:** shadcn/ui
*   **AI/ML Integration:** Genkit

### File Structure Overview

The project is organized logically to separate concerns and promote maintainability.

```
/src
├── app/
│   ├── page.tsx          # Main entry point, handles device selection vs. dashboard view
│   ├── layout.tsx        # Root layout of the application
│   └── globals.css       # Global styles and Tailwind CSS theme configuration
│
├── components/
│   ├── ui/               # Core shadcn/ui components (Button, Card, etc.)
│   ├── dashboard-layout.tsx # Main layout for the authenticated/device-selected view
│   ├── device-selection.tsx # The initial screen to select a target device
│   ├── terminal.tsx      # A simulated terminal component
│   ├── settings.tsx      # The settings panel for managing devices and campaign config
│   └── ...               # Other reusable components (Sidebar, TopNav, etc.)
│
├── lib/
│   ├── types.ts          # TypeScript type definitions for objects like Device
│   ├── utils.ts          # Utility functions (e.g., cn for class names)
│   └── mock-data.ts      # Mock data for frontend development without a live backend
│
└── ai/
    ├── genkit.ts         # Genkit configuration and initialization
    └── flows/            # AI flows, e.g., for command suggestions
```

## 3. Key Architectural Concepts

### Component-Based Design

The UI is broken down into small, reusable React components located in `src/components/`. This approach makes the codebase easier to manage, test, and scale. Core UI elements are based on `shadcn/ui`, which provides a set of accessible and stylable "unstyled" components.

### State Management

*   **Local State:** For component-level state (e.g., dialog visibility, input values), we use React's built-in `useState` and `useReducer` hooks.
*   **Global State:** For state that needs to be shared across the application (like the currently selected device), we lift the state up to the nearest common ancestor, which is typically `src/app/page.tsx`. For more complex scenarios, React Context could be integrated.

### Layout & Routing

*   **App Router:** Next.js's App Router is used for all routing and layout management.
*   **`layout.tsx`:** Defines the root HTML shell, including fonts and the global `Toaster` component for notifications.
*   **`page.tsx`:** Acts as a controller, conditionally rendering either the `DeviceSelection` component or the `DashboardLayout` component based on whether a device is selected.
*   **`DashboardLayout.tsx`:** Contains the main dashboard structure, including the collapsible sidebar and the top navigation bar, which controls the main content area.

## 4. How to Connect to a Live Backend

The current implementation is fully frontend-only and uses mock data from `src/lib/mock-data.ts`. To make the application production-ready, you need to replace this mock data with live data from your C2 backend API.

### Steps for Integration:

1.  **Define API Endpoints:** First, ensure your backend exposes a clear REST or GraphQL API for actions like:
    *   `GET /api/devices`: Fetch all available devices.
    *   `GET /api/devices/{guid}`: Fetch detailed information for a single device.
    *   `POST /api/devices/{guid}/rename`: Update a device's name.
    *   `DELETE /api/devices/{guid}`: Uninstall the agent and remove the device.
    *   `GET /api/devices/{guid}/call-log`: Get call log data.
    *   `POST /api/devices/{guid}/command`: Execute a command on the device.

2.  **Replace Mock Data Fetching:**
    *   In `src/app/page.tsx`, replace the `initialMockDevices` import with a `fetch` call to your `GET /api/devices` endpoint inside a `useEffect` hook.
    *   Update the `devices` state with the fetched data.

    ```tsx
    // Example in src/app/page.tsx
    useEffect(() => {
      const fetchDevices = async () => {
        try {
          const response = await fetch('/api/devices'); // Your backend endpoint
          const data = await response.json();
          setDevices(data);
        } catch (error) {
          console.error("Failed to fetch devices:", error);
          // Handle error, e.g., show a toast notification
        }
      };
      fetchDevices();
    }, []);
    ```

3.  **Implement API Calls for Actions:**
    *   **Edit Name:** In `DashboardLayout.tsx`, the `handleDeviceNameSave` function should make a `POST` request to your backend to save the new name.
    *   **Delete Agent:** In `DashboardLayout.tsx`, the `handleDeleteAgent` function should make a `DELETE` request to your backend.
    *   **Fetch Tab-Specific Data:** Inside each tab's component (e.g., when the "Call Log" tab is active), use a `useEffect` hook that triggers when `selectedDevice` changes to fetch the relevant data (e.g., from `/api/devices/{guid}/call-log`).

## 5. How to Expand the Dashboard

The modular architecture makes it straightforward to add new features.

### Adding a New Feature Tab:

1.  **Add Icon to TopNav:** In `src/components/dashboard-layout.tsx`, add a new `TopNavItem` to the `TopNav` component. Give it a unique `onClick` handler to set a new active tab value.

    ```tsx
    // In DashboardLayout
    <TopNavItem
      icon={<NewIcon />}
      label="New Feature"
      isActive={activeTab === 'new_feature'}
      onClick={() => setActiveTab('new_feature')}
    />
    ```

2.  **Add Content Area:** In the `main` section of `DashboardLayout`, add a new conditional block to render your feature's component when its tab is active.

    ```tsx
    // In DashboardLayout
    {activeTab === 'new_feature' && (
      <NewFeatureComponent device={selectedDevice} />
    )}
    ```

3.  **Create the Component:** Create your new component (e.g., `src/components/new-feature.tsx`). This component can fetch its own data based on the `device` prop passed to it.

### Integrating New AI Features

*   **Create a Genkit Flow:** Define a new flow in `src/ai/flows/` for your desired functionality (e.g., analyzing a screenshot, summarizing device activity). Define clear Zod schemas for the input and output.
*   **Call from UI:** Create a new server action