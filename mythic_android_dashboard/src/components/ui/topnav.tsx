
"use client"

import * as React from "react"
import { cn } from "@/lib/utils"
import { Button } from "./button";
import { ChevronLeft, ChevronRight } from "lucide-react";

export const TopNav = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, children, ...props }, ref) => {
  const navRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    // Adding a simple utility class to hide the scrollbar
    const styleId = 'scrollbar-hide-style';
    if (document.getElementById(styleId)) {
      return;
    }
    const style = document.createElement('style');
    style.id = styleId;
    style.innerHTML = `
      .scrollbar-hide::-webkit-scrollbar {
        display: none;
      }
      .scrollbar-hide {
        -ms-overflow-style: none;
        scrollbar-width: none;
      }
    `;
    document.head.appendChild(style);
  }, []);

  const scrollLeft = () => {
    if (navRef.current) {
      navRef.current.scrollBy({ left: -150, behavior: 'smooth' });
    }
  };

  const scrollRight = () => {
    if (navRef.current) {
      navRef.current.scrollBy({ left: 150, behavior: 'smooth' });
    }
  };

  return (
    <div className="flex items-center justify-center p-2 bg-card border-b-2 border-border/60 shadow-lg">
      <Button variant="ghost" size="icon" onClick={scrollLeft} className="h-12 w-12 rounded-full">
        <ChevronLeft className="h-6 w-6" />
      </Button>
      <nav
        ref={navRef}
        className={cn(
          "flex items-center space-x-2 overflow-x-auto mx-2",
          "scrollbar-hide", // Utility class to hide scrollbar
          className
        )}
        {...props}
      >
        {children}
      </nav>
      <Button variant="ghost" size="icon" onClick={scrollRight} className="h-12 w-12 rounded-full">
        <ChevronRight className="h-6 w-6" />
      </Button>
    </div>
  );
});
TopNav.displayName = "TopNav";

export const TopNavItem = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & {
    icon: React.ReactNode;
    label: string;
    count?: number;
    hasNotification?: boolean;
    isActive?: boolean;
  }
>(({ className, icon, label, count, hasNotification, isActive, ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      "flex flex-col items-center justify-center text-center text-foreground cursor-pointer group flex-shrink-0",
      className
    )}
    {...props}
  >
    <div
      className={cn(
        "relative w-12 h-12 flex items-center justify-center rounded-full bg-muted/40 border-2 border-muted group-hover:bg-ring/20 group-hover:border-ring transition-all duration-300",
        "shadow-[0_0_10px_rgba(41,121,255,0.3)]",
        isActive && "bg-ring/30 border-ring"
      )}
    >
      {icon}
      {hasNotification && (
        <span className="absolute top-0 right-0 block h-3 w-3 rounded-full bg-destructive ring-2 ring-background" />
      )}
    </div>
    <span className="mt-1 text-xs font-medium">{label}</span>
    {count !== undefined && (
      <span className="text-xs text-muted-foreground">({count})</span>
    )}
  </div>
));
TopNavItem.displayName = "TopNavItem";
