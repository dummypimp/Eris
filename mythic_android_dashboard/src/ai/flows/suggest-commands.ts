'use server';

/**
 * @fileOverview Implements the AI-powered command suggestion flow.
 *
 * - suggestCommands - A function that suggests relevant commands based on device, context, and history.
 * - SuggestCommandsInput - The input type for the suggestCommands function.
 * - SuggestCommandsOutput - The return type for the suggestCommands function.
 */

import {ai} from '@/ai/genkit';
import {z} from 'genkit';

const SuggestCommandsInputSchema = z.object({
  deviceType: z.string().describe('The type of the connected device (e.g., Android phone, Android tablet).'),
  currentContext: z.string().describe('The current context or task the user is performing (e.g., browsing files, managing modules).'),
  pastCommands: z.array(z.string()).describe('An array of previously executed commands on the device.'),
});
export type SuggestCommandsInput = z.infer<typeof SuggestCommandsInputSchema>;

const SuggestCommandsOutputSchema = z.object({
  suggestedCommands: z.array(z.string()).describe('An array of suggested commands based on the input criteria.'),
});
export type SuggestCommandsOutput = z.infer<typeof SuggestCommandsOutputSchema>;

export async function suggestCommands(input: SuggestCommandsInput): Promise<SuggestCommandsOutput> {
  return suggestCommandsFlow(input);
}

const prompt = ai.definePrompt({
  name: 'suggestCommandsPrompt',
  input: {schema: SuggestCommandsInputSchema},
  output: {schema: SuggestCommandsOutputSchema},
  prompt: `You are an AI assistant that suggests relevant commands for an Android command and control tool.

  Based on the device type, current context, and past command history, suggest the most relevant commands the user might want to execute.

  Device Type: {{{deviceType}}}
  Current Context: {{{currentContext}}}
  Past Commands: {{#if pastCommands}}
  {{#each pastCommands}}- {{{this}}}\n{{/each}}
  {{else}}
  No past commands.
  {{/if}}

  Suggest the most appropriate commands:
  `, config: {
    safetySettings: [
      {
        category: 'HARM_CATEGORY_DANGEROUS_CONTENT',
        threshold: 'BLOCK_ONLY_HIGH',
      },
    ],
  },
});

const suggestCommandsFlow = ai.defineFlow(
  {
    name: 'suggestCommandsFlow',
    inputSchema: SuggestCommandsInputSchema,
    outputSchema: SuggestCommandsOutputSchema,
  },
  async input => {
    const {output} = await prompt(input);
    return output!;
  }
);

