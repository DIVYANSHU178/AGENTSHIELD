import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { MotionProvider, useMotion } from './MotionContext';

const TestMotionConsumer: React.FC = () => {
  const { isReducedMotion, userMotionPreference, setUserMotionPreference } = useMotion();

  return (
    <div>
      <span data-testid="is-reduced">{String(isReducedMotion)}</span>
      <span data-testid="user-pref">{userMotionPreference}</span>
      <button onClick={() => setUserMotionPreference('reduced')}>Set Reduced</button>
      <button onClick={() => setUserMotionPreference('full')}>Set Full</button>
      <button onClick={() => setUserMotionPreference('system')}>Set System</button>
    </div>
  );
};

describe('MotionContext and useMotion', () => {
  const storageMock: Record<string, string> = {};

  beforeEach(() => {
    Object.keys(storageMock).forEach((k) => delete storageMock[k]);
    Object.defineProperty(window, 'localStorage', {
      value: {
        getItem: (key: string) => storageMock[key] ?? null,
        setItem: (key: string, value: string) => {
          storageMock[key] = String(value);
        },
        removeItem: (key: string) => {
          delete storageMock[key];
        },
        clear: () => {
          Object.keys(storageMock).forEach((k) => delete storageMock[k]);
        },
      },
      writable: true,
      configurable: true,
    });
  });

  it('provides default motion settings and responds to user preference switches', () => {
    render(
      <MotionProvider>
        <TestMotionConsumer />
      </MotionProvider>
    );

    expect(screen.getByTestId('user-pref')).toHaveTextContent('system');

    // Switch to reduced
    fireEvent.click(screen.getByText('Set Reduced'));
    expect(screen.getByTestId('is-reduced')).toHaveTextContent('true');
    expect(screen.getByTestId('user-pref')).toHaveTextContent('reduced');
    expect(window.localStorage.getItem('agentshield_motion_preference')).toBe('reduced');

    // Switch to full
    fireEvent.click(screen.getByText('Set Full'));
    expect(screen.getByTestId('is-reduced')).toHaveTextContent('false');
    expect(screen.getByTestId('user-pref')).toHaveTextContent('full');
    expect(window.localStorage.getItem('agentshield_motion_preference')).toBe('full');
  });

  it('provides safe fallback if used outside MotionProvider', () => {
    render(<TestMotionConsumer />);
    expect(screen.getByTestId('user-pref')).toHaveTextContent('system');
  });
});
