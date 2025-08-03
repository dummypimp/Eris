
export interface Device {
    name: string;
    guid: string;
    status: 'active' | 'inactive';
    hasNotification: boolean;
    ip: string;
    os: string;
    connectionType: string;
}

export interface Call {
    name: string | null;
    number: string;
    type: 'Outgoing' | 'Incoming' | 'Missed';
    date: string;
    duration: string;
}

export interface Sms {
    from: string;
    message: string;
    date: string;
}
