"use client";

import { useState } from "react";
import { suggestCommands, SuggestCommandsInput } from "@/ai/flows/suggest-commands";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Bot, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";

interface AiCommandSuggestionsProps extends Omit<SuggestCommandsInput, 'pastCommands'> {
  pastCommands: string[];
  onSelectSuggestion: (suggestion: string) => void;
}

export function AiCommandSuggestions({ deviceType, currentContext, pastCommands, onSelectSuggestion }: AiCommandSuggestionsProps) {
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const { toast } = useToast();

  const handleFetchSuggestions = async () => {
    setIsLoading(true);
    try {
      const result = await suggestCommands({
        deviceType,
        currentContext,
        pastCommands: pastCommands.slice(-5), // Send last 5 commands for context
      });
      setSuggestions(result.suggestedCommands);
    } catch (error) {
      console.error("AI suggestion error:", error);
      toast({
        variant: "destructive",
        title: "AI Error",
        description: "Could not fetch command suggestions.",
      });
      setSuggestions([]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="icon" onClick={handleFetchSuggestions} disabled={isLoading}>
          {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Bot className="h-4 w-4" />}
          <span className="sr-only">Get AI Suggestions</span>
        </Button>
      </PopoverTrigger>
      <PopoverContent className="p-0" align="end">
        <Command>
          <CommandInput placeholder="Filter suggestions..." />
          <CommandList>
            <CommandEmpty>{isLoading ? "Loading suggestions..." : "No suggestions found."}</CommandEmpty>
            <CommandGroup heading="Suggested Commands">
              {suggestions.map((suggestion, index) => (
                <CommandItem
                  key={index}
                  onSelect={() => {
                    onSelectSuggestion(suggestion);
                    setOpen(false);
                  }}
                >
                  {suggestion}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
