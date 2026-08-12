import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import App from './App';

global.fetch = vi.fn().mockImplementation(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve({ status: 'ok', service: 'agentshield' }),
  })
);

describe('App Foundation', () => {
  it('renders AgentShield title and tagline correctly', async () => {
    render(<App />);
    expect(screen.getAllByText('AgentShield')[0]).toBeInTheDocument();
    expect(screen.getByText('The Security Layer for Autonomous AI Agents')).toBeInTheDocument();
    
    await waitFor(() => {
      expect(screen.getByText('Online')).toBeInTheDocument();
    });
  });

  it('renders core architectural principle statement', async () => {
    render(<App />);
    expect(
      screen.getByText(
        /"The AI agent must never directly execute a tool. Every tool request must pass through AgentShield's security boundary before execution."/i
      )
    ).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('Online')).toBeInTheDocument();
    });
  });
});
