"use client";
import * as React from 'react';

interface HeaderProps extends React.HTMLAttributes<HTMLDivElement> {
    title: string;
    description?: string;
}

export const Header = ({ title, description, children }: HeaderProps) => {
    return (
        <div className="flex items-center justify-between p-4">
            <div className='flex flex-col gap-1'>
                <h1 className="text-4xl font-bold">{title}</h1>
                {description && <p className="text-muted-foreground mt-2">{description}</p>}
            </div>
            <div>
                {children}
            </div>
        </div>
    )
}