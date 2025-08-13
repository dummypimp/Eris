"use client";

import { useState, useEffect } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { apiClient } from "@/lib/api-client";
import { wsClient } from "@/lib/websocket-client";
import { useToast } from "@/hooks/use-toast";
import { Command } from "@/lib/types";

interface TerminalProps {
  deviceId: string;
  deviceType: string;
  currentContext: string;
}

interface TerminalHistoryItem {
  type: 'command' | 'output' | 'error';
  content: string;
  timestamp: number;
}

export function Terminal({ deviceId, deviceType, currentContext }: TerminalProps) {
  const [commandHistory, setCommandHistory] = useState<TerminalHistoryItem[]>([]);
  const [input, setInput] = useState("");
  const [isExecuting, setIsExecuting] = useState(false);
  const [commands, setCommands] = useState<Command[]>([]);
  const { toast } = useToast();

  useEffect(() => {

    loadRecentCommands();

    wsClient.on('command_result', handleCommandResult);

    return () => {
      wsClient.off('command_result', handleCommandResult);
    };
  }, [deviceId]);

  const loadRecentCommands = async () => {
    try {
      const response = await apiClient.getCommands(deviceId, 50);
      if (response.success && response.data) {
        setCommands(response.data);

        const recentHistory: TerminalHistoryItem[] = [];
        response.data.slice(-10).forEach(cmd => {
          recentHistory.push({
            type: 'command',
            content: `shell@android:~$ ${cmd.command}`,
            timestamp: cmd.timestamp
          });

          if (cmd.result) {
            recentHistory.push({
              type: 'output',
              content: cmd.result,
              timestamp: cmd.timestamp + 1
            });
          }

          if (cmd.error) {
            recentHistory.push({
              type: 'error',
              content: cmd.error,
              timestamp: cmd.timestamp + 1
            });
          }
        });

        setCommandHistory(recentHistory);
      }
    } catch (error) {
      console.error('Failed to load commands:', error);
    }
  };

  const handleCommandResult = (command: Command) => {
    if (command.deviceId !== deviceId) return;

    setIsExecuting(false);

    if (command.result) {
      setCommandHistory(prev => [...prev, {
        type: 'output',
        content: command.result!,
        timestamp: Date.now()
      }]);
    }

    if (command.error) {
      setCommandHistory(prev => [...prev, {
        type: 'error',
        content: command.error!,
        timestamp: Date.now()
      }]);
    }

    setCommands(prev => prev.map(cmd =>
      cmd.id === command.id ? command : cmd
    ));
  };

  const handleCommandSubmit = async (command: string) => {
    if (command.trim() === "" || isExecuting) return;

    const trimmedCommand = command.trim();

    setCommandHistory(prev => [...prev, {
      type: 'command',
      content: `shell@android:~$ ${trimmedCommand}`,
      timestamp: Date.now()
    }]);

    setInput("");
    setIsExecuting(true);

    try {
      const response = await apiClient.executeCommand(deviceId, trimmedCommand);

      if (response.success && response.data) {

        setCommandHistory(prev => [...prev, {
          type: 'output',
          content: 'Command submitted. Waiting for response...',
          timestamp: Date.now()
        }]);

        setCommands(prev => [response.data!, ...prev]);
      } else {
        setIsExecuting(false);
        setCommandHistory(prev => [...prev, {
          type: 'error',
          content: response.error || 'Failed to execute command',
          timestamp: Date.now()
        }]);

        toast({
          variant: 'destructive',
          title: 'Command Failed',
          description: response.error || 'Failed to execute command'
        });
      }
    } catch (error) {
      setIsExecuting(false);
      setCommandHistory(prev => [...prev, {
        type: 'error',
        content: 'Network error: Unable to execute command',
        timestamp: Date.now()
      }]);

      toast({
        variant: 'destructive',
        title: 'Network Error',
        description: 'Unable to execute command'
      });
    }
  };

  const getHistoryItemColor = (type: string) => {
    switch (type) {
      case 'command': return 'text-green-400';
      case 'output': return 'text-white';
      case 'error': return 'text-red-400';
      default: return 'text-white';
    }
  };

  return (
    <div className="bg-[#282c34] rounded-lg shadow-2xl h-[600px] flex flex-col font-code">
      <div className="bg-card/80 p-2 rounded-t-lg flex items-center justify-between">
        <div className="flex space-x-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div className="w-3 h-3 rounded-full bg-green-500"></div>
        </div>
        <p className="text-sm text-center flex-1 text-muted-foreground">Terminal - {currentContext}</p>
        <div className="flex items-center space-x-2">
          {isExecuting && (
            <div className="flex items-center space-x-1 text-xs text-yellow-400">
              <div className="w-2 h-2 bg-yellow-400 rounded-full animate-pulse"></div>
              <span>Executing...</span>
            </div>
          )}
          <span className="text-xs text-muted-foreground">{commands.length} commands</span>
        </div>
      </div>

      <div className="flex-1 p-4 overflow-y-auto text-white space-y-1">
        {commandHistory.length === 0 && (
          <div className="text-center text-muted-foreground py-8">
            <p>Terminal ready. Type a command to get started.</p>
            <p className="text-sm mt-2">Try: <code className="bg-muted px-1 rounded">ls</code>, <code className="bg-muted px-1 rounded">pwd</code>, <code className="bg-muted px-1 rounded">whoami</code></p>
          </div>
        )}
        {commandHistory.map((item, index) => (
          <div key={index} className={`whitespace-pre-wrap ${getHistoryItemColor(item.type)}`}>
            {item.content}
          </div>
        ))}
      </div>

      <div className="p-2 border-t border-border bg-card/80 flex items-center gap-2">
        <span className="text-green-400">shell@android:~$</span>
        <Input
          className="flex-1 bg-transparent border-none text-white focus:ring-0 disabled:opacity-50"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !isExecuting) {
              handleCommandSubmit(input);
            }
          }}
          placeholder={isExecuting ? "Executing command..." : "Enter command..."}
          disabled={isExecuting}
        />
        <Button
          onClick={() => handleCommandSubmit(input)}
          size="sm"
          disabled={isExecuting || !input.trim()}
        >
          {isExecuting ? 'Executing...' : 'Send'}
        </Button>
      </div>
    </div>
  );
}