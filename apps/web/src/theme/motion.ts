/**
 * AgentShield Central Motion System
 * Phase 14J-C1 UI Hardening Foundation
 *
 * Cinematic, restrained, professional animation presets and transition primitives
 * engineered for high-performance security operations consoles.
 *
 * Fully respects `prefers-reduced-motion` with zero-overhead fallback paths.
 */

import { type Variants, type Transition } from 'framer-motion';

/**
 * High-tech deceleration curves (ease-out-expo / crisp security deceleration).
 * Prevents cartoonish bouncing while preserving snappy, mechanical precision.
 */
export const easings = {
  // Precision technical ease-out for entering surfaces
  technical: [0.16, 1, 0.3, 1] as [number, number, number, number],
  // Smooth symmetric curve for crossfades
  smooth: [0.4, 0, 0.2, 1] as [number, number, number, number],
  // Snappy exit curve
  exit: [0.7, 0, 0.84, 0] as [number, number, number, number],
  // Linear for deterministic indicators
  linear: [0, 0, 1, 1] as [number, number, number, number],
} as const;

export const durations = {
  instant: 0,
  micro: 0.1,    // 100ms: micro-interactions, button active states
  fast: 0.18,    // 180ms: row reveals, popovers, dropdowns
  normal: 0.25,  // 250ms: tab transitions, cards, modals
  page: 0.32,    // 320ms: full page enters
  pulse: 2.0,    // 2000ms: gentle breathing status pulse
} as const;

export const transitions = {
  fast: {
    duration: durations.fast,
    ease: easings.technical,
  } as Transition,
  normal: {
    duration: durations.normal,
    ease: easings.technical,
  } as Transition,
  page: {
    duration: durations.page,
    ease: easings.technical,
  } as Transition,
  reduced: {
    duration: 0,
    ease: 'linear',
  } as Transition,
} as const;

// ---------------------------------------------------------------------------
// 1. Full Page Enter / Exit Variants
// ---------------------------------------------------------------------------
export const pageVariants: Variants = {
  initial: {
    opacity: 0,
    y: 8,
  },
  animate: {
    opacity: 1,
    y: 0,
    transition: {
      duration: durations.page,
      ease: easings.technical,
      when: 'beforeChildren',
    },
  },
  exit: {
    opacity: 0,
    y: -4,
    transition: {
      duration: durations.fast,
      ease: easings.exit,
    },
  },
};

// ---------------------------------------------------------------------------
// 2. Modal Scrim Backdrop & Dialog Enter / Exit
// ---------------------------------------------------------------------------
export const backdropVariants: Variants = {
  initial: { opacity: 0 },
  animate: {
    opacity: 1,
    transition: { duration: durations.fast, ease: easings.smooth },
  },
  exit: {
    opacity: 0,
    transition: { duration: durations.micro, ease: easings.exit },
  },
};

export const modalVariants: Variants = {
  initial: {
    opacity: 0,
    scale: 0.97,
    y: 10,
  },
  animate: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: {
      duration: durations.normal,
      ease: easings.technical,
    },
  },
  exit: {
    opacity: 0,
    scale: 0.98,
    y: 6,
    transition: {
      duration: durations.fast,
      ease: easings.exit,
    },
  },
};

// ---------------------------------------------------------------------------
// 3. Card Reveal & Stagger Orchestration
// ---------------------------------------------------------------------------
export const staggerContainerVariants: Variants = {
  initial: { opacity: 0 },
  animate: {
    opacity: 1,
    transition: {
      staggerChildren: 0.04,
      delayChildren: 0.02,
    },
  },
  exit: {
    opacity: 0,
    transition: { staggerChildren: 0.02, staggerDirection: -1 },
  },
};

export const cardVariants: Variants = {
  initial: {
    opacity: 0,
    y: 12,
  },
  animate: {
    opacity: 1,
    y: 0,
    transition: {
      duration: durations.normal,
      ease: easings.technical,
    },
  },
  exit: {
    opacity: 0,
    y: -6,
    transition: {
      duration: durations.fast,
      ease: easings.exit,
    },
  },
};

// ---------------------------------------------------------------------------
// 4. Table / Row Item Reveal
// ---------------------------------------------------------------------------
export const rowVariants: Variants = {
  initial: {
    opacity: 0,
    x: -4,
  },
  animate: {
    opacity: 1,
    x: 0,
    transition: {
      duration: durations.fast,
      ease: easings.technical,
    },
  },
  exit: {
    opacity: 0,
    x: 4,
    transition: {
      duration: durations.micro,
      ease: easings.exit,
    },
  },
};

// ---------------------------------------------------------------------------
// 5. Tab View Transitions (Crossfade with subtle drift)
// ---------------------------------------------------------------------------
export const tabVariants: Variants = {
  initial: {
    opacity: 0,
    y: 6,
  },
  animate: {
    opacity: 1,
    y: 0,
    transition: {
      duration: durations.fast,
      ease: easings.technical,
    },
  },
  exit: {
    opacity: 0,
    y: -4,
    transition: {
      duration: durations.micro,
      ease: easings.exit,
    },
  },
};

// ---------------------------------------------------------------------------
// 6. Notification / Toast Banner Slide
// ---------------------------------------------------------------------------
export const toastVariants: Variants = {
  initial: {
    opacity: 0,
    y: -14,
    scale: 0.98,
  },
  animate: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: {
      duration: durations.normal,
      ease: easings.technical,
    },
  },
  exit: {
    opacity: 0,
    y: -10,
    scale: 0.98,
    transition: {
      duration: durations.fast,
      ease: easings.exit,
    },
  },
};

// ---------------------------------------------------------------------------
// 7. Security Indicator & State Pulses (Gentle Breathing)
// ---------------------------------------------------------------------------
export const statusPulseVariants: Variants = {
  initial: { opacity: 0.7, scale: 0.95 },
  animate: {
    opacity: [0.7, 1, 0.7],
    scale: [0.95, 1.05, 0.95],
    transition: {
      duration: durations.pulse,
      repeat: Infinity,
      ease: 'easeInOut',
    },
  },
};

// ---------------------------------------------------------------------------
// 8. Reduced Motion Variant Fallbacks (Zero transform, instant or pure opacity)
// ---------------------------------------------------------------------------
export const reducedMotionVariants: Record<string, Variants> = {
  page: {
    initial: { opacity: 0 },
    animate: { opacity: 1, transition: { duration: durations.fast } },
    exit: { opacity: 0, transition: { duration: durations.micro } },
  },
  modal: {
    initial: { opacity: 0 },
    animate: { opacity: 1, transition: { duration: durations.fast } },
    exit: { opacity: 0, transition: { duration: durations.micro } },
  },
  card: {
    initial: { opacity: 0 },
    animate: { opacity: 1, transition: { duration: durations.fast } },
    exit: { opacity: 0, transition: { duration: durations.micro } },
  },
  row: {
    initial: { opacity: 0 },
    animate: { opacity: 1, transition: { duration: durations.micro } },
    exit: { opacity: 0, transition: { duration: durations.micro } },
  },
  tab: {
    initial: { opacity: 0 },
    animate: { opacity: 1, transition: { duration: durations.micro } },
    exit: { opacity: 0, transition: { duration: durations.micro } },
  },
  toast: {
    initial: { opacity: 0 },
    animate: { opacity: 1, transition: { duration: durations.micro } },
    exit: { opacity: 0, transition: { duration: durations.micro } },
  },
  pulse: {
    initial: { opacity: 1 },
    animate: { opacity: 1 },
  },
  container: {
    initial: { opacity: 0 },
    animate: { opacity: 1, transition: { duration: 0 } },
    exit: { opacity: 0, transition: { duration: 0 } },
  },
};

/**
 * Helper to select active variant mapping depending on reduced motion preference.
 */
export function getMotionVariant(name: 'page' | 'modal' | 'card' | 'row' | 'tab' | 'toast' | 'pulse' | 'container', isReduced: boolean): Variants {
  if (isReduced) {
    return reducedMotionVariants[name] || reducedMotionVariants.page;
  }
  switch (name) {
    case 'page':
      return pageVariants;
    case 'modal':
      return modalVariants;
    case 'card':
      return cardVariants;
    case 'row':
      return rowVariants;
    case 'tab':
      return tabVariants;
    case 'toast':
      return toastVariants;
    case 'pulse':
      return statusPulseVariants;
    case 'container':
      return staggerContainerVariants;
    default:
      return pageVariants;
  }
}
