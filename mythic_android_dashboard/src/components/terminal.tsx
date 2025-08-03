
"use client";

import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

interface TerminalProps {
  deviceType: string;
  currentContext: string;
}

export function Terminal({ deviceType, currentContext }: TerminalProps) {
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [input, setInput] = useState("");

  const handleCommandSubmit = (command: string) => {
    if (command.trim() === "") return;
    setCommandHistory(prev => [...prev, `shell@android:~$ ${command}`, `Executing: ${command}...`]);
    setInput("");
    // In a real scenario, you would execute the command here
  };

  const handleSelectSuggestion = (suggestion: string) => {
    setInput(suggestion);
  };

  return (
    <div className="bg-[#282c34] rounded-lg shadow-2xl h-[600px] flex flex-col font-code">
      <div className="bg-card/80 p-2 rounded-t-lg flex items-center">
        <div className="flex space-x-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div className="w-3 h-3 rounded-full bg-green-500"></div>
        </div>
        <p className="text-sm text-center flex-1 text-muted-foreground">Terminal</p>
      </div>
      <div className="flex-1 p-4 overflow-y-auto text-white">
        {commandHistory.map((line, index) => (
          <p key={index} className="whitespace-pre-wrap">{line}</p>
        ))}
      </div>
      <div className="p-2 border-t border-border bg-card/80 flex items-center gap-2">
        <span className="text-green-400">shell@android:~$</span>
        <Input
          className="flex-1 bg-transparent border-none text-white focus:ring-0"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              handleCommandSubmit(input);
            }
          }}
          placeholder="Enter command..."
        />
        <Button onClick={() => handleCommandSubmit(input)} size="sm">
            Send
        </Button>
      </div>
    </div>
  );
}
