import type {Metadata} from 'next';
import { Toaster } from "@/components/ui/toaster"
import './globals.css';

export const metadata: Metadata = {
  title: 'Eris Dashboard - Android Command & Control',
  description: 'Eris Android Command & Control Dashboard - Comprehensive mobile device management and surveillance platform',
  icons: {
    icon: '/Eris.svg',
    shortcut: '/Eris.png',
    apple: '/Eris.png',
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https:
        <link rel="preconnect" href="https:
        <link href="https:
        <link href="https:
      </head>
      <body className="font-sans antialiased">
        {children}
        <Toaster />
      </body>
    </html>
  );
}