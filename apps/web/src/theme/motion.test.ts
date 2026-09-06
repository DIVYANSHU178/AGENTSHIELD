import { describe, it, expect } from 'vitest';
import {
  easings,
  durations,
  transitions,
  pageVariants,
  modalVariants,
  cardVariants,
  rowVariants,
  tabVariants,
  toastVariants,
  statusPulseVariants,
  reducedMotionVariants,
  getMotionVariant,
} from './motion';

describe('AgentShield Central Motion System', () => {
  it('defines restrained deceleration curves and timing', () => {
    expect(easings.technical).toEqual([0.16, 1, 0.3, 1]);
    expect(durations.micro).toBe(0.1);
    expect(durations.fast).toBe(0.18);
    expect(durations.normal).toBe(0.25);
    expect(durations.page).toBe(0.32);
    expect(durations.pulse).toBe(2.0);
    expect((transitions.fast as any).duration).toBe(0.18);
  });

  it('defines standard motion variants with entry and exit states', () => {
    // Page
    expect(pageVariants.initial).toMatchObject({ opacity: 0, y: 8 });
    expect(pageVariants.animate).toMatchObject({ opacity: 1, y: 0 });

    // Modal
    expect(modalVariants.initial).toMatchObject({ opacity: 0, scale: 0.97 });
    expect(modalVariants.animate).toMatchObject({ opacity: 1, scale: 1 });

    // Card
    expect(cardVariants.initial).toMatchObject({ opacity: 0, y: 12 });
    expect(cardVariants.animate).toMatchObject({ opacity: 1, y: 0 });

    // Row
    expect(rowVariants.initial).toMatchObject({ opacity: 0, x: -4 });
    expect(rowVariants.animate).toMatchObject({ opacity: 1, x: 0 });

    // Tab
    expect(tabVariants.initial).toMatchObject({ opacity: 0, y: 6 });
    expect(tabVariants.animate).toMatchObject({ opacity: 1, y: 0 });

    // Toast
    expect(toastVariants.initial).toMatchObject({ opacity: 0, y: -14 });
    expect(toastVariants.animate).toMatchObject({ opacity: 1, y: 0 });

    // Pulse
    expect(statusPulseVariants.animate).toHaveProperty('opacity');
    expect(statusPulseVariants.animate).toHaveProperty('scale');
  });

  it('defines reduced-motion fallbacks without transform translations or scaling', () => {
    Object.values(reducedMotionVariants).forEach((variant) => {
      // Must not have y or x or scale
      expect(variant.initial).not.toHaveProperty('y');
      expect(variant.initial).not.toHaveProperty('x');
      expect(variant.initial).not.toHaveProperty('scale');


      if (variant.animate && !Array.isArray(variant.animate)) {
        expect(variant.animate).not.toHaveProperty('y');
        expect(variant.animate).not.toHaveProperty('x');
        expect(variant.animate).not.toHaveProperty('scale');
      }
    });
  });

  it('getMotionVariant selects standard variants when reduced motion is disabled', () => {
    expect(getMotionVariant('page', false)).toBe(pageVariants);
    expect(getMotionVariant('modal', false)).toBe(modalVariants);
    expect(getMotionVariant('card', false)).toBe(cardVariants);
    expect(getMotionVariant('row', false)).toBe(rowVariants);
    expect(getMotionVariant('tab', false)).toBe(tabVariants);
    expect(getMotionVariant('toast', false)).toBe(toastVariants);
    expect(getMotionVariant('pulse', false)).toBe(statusPulseVariants);
  });

  it('getMotionVariant selects reduced variants when reduced motion is active', () => {
    expect(getMotionVariant('page', true)).toBe(reducedMotionVariants.page);
    expect(getMotionVariant('modal', true)).toBe(reducedMotionVariants.modal);
    expect(getMotionVariant('card', true)).toBe(reducedMotionVariants.card);
    expect(getMotionVariant('row', true)).toBe(reducedMotionVariants.row);
    expect(getMotionVariant('tab', true)).toBe(reducedMotionVariants.tab);
    expect(getMotionVariant('toast', true)).toBe(reducedMotionVariants.toast);
    expect(getMotionVariant('pulse', true)).toBe(reducedMotionVariants.pulse);
  });
});
