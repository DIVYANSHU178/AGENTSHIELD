/**
 * AgentShield Motion Primitives
 * Phase 14J-C1 UI Hardening Foundation
 *
 * Lightweight, accessible, GPU-accelerated motion wrappers that automatically adapt
 * to user and system motion reduction preferences.
 */

import React from 'react';
import { motion, type HTMLMotionProps } from 'framer-motion';
import { useMotion } from '../../context/MotionContext';
import { backdropVariants } from '../../theme/motion';

export interface MotionPageProps extends HTMLMotionProps<'div'> {
  children: React.ReactNode;
}

export const MotionPage: React.FC<MotionPageProps> = ({ children, className = '', ...props }) => {
  const { getVariant } = useMotion();
  const variants = getVariant('page');

  return (
    <motion.div
      variants={variants}
      initial="initial"
      animate="animate"
      exit="exit"
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
};

export interface MotionCardProps extends HTMLMotionProps<'div'> {
  children: React.ReactNode;
}

export const MotionCard: React.FC<MotionCardProps> = ({ children, className = '', ...props }) => {
  const { getVariant } = useMotion();
  const variants = getVariant('card');

  return (
    <motion.div
      variants={variants}
      initial="initial"
      animate="animate"
      exit="exit"
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
};

export interface MotionListProps extends HTMLMotionProps<'div'> {
  children: React.ReactNode;
}

export const MotionList: React.FC<MotionListProps> = ({ children, className = '', ...props }) => {
  const { getVariant } = useMotion();
  const variants = getVariant('container');

  return (
    <motion.div
      variants={variants}
      initial="initial"
      animate="animate"
      exit="exit"
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
};

export interface MotionItemProps extends HTMLMotionProps<'div'> {
  children: React.ReactNode;
}

export const MotionItem: React.FC<MotionItemProps> = ({ children, className = '', ...props }) => {
  const { getVariant } = useMotion();
  const variants = getVariant('row');

  return (
    <motion.div
      variants={variants}
      initial="initial"
      animate="animate"
      exit="exit"
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
};

export interface MotionTabPanelProps extends HTMLMotionProps<'div'> {
  children: React.ReactNode;
  tabKey: string;
}

export const MotionTabPanel: React.FC<MotionTabPanelProps> = ({
  children,
  tabKey,
  className = '',
  ...props
}) => {
  const { getVariant } = useMotion();
  const variants = getVariant('tab');

  return (
    <motion.div
      key={tabKey}
      variants={variants}
      initial="initial"
      animate="animate"
      exit="exit"
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
};

export interface MotionModalProps extends HTMLMotionProps<'div'> {
  children: React.ReactNode;
}

export const MotionModal: React.FC<MotionModalProps> = ({ children, className = '', ...props }) => {
  const { getVariant } = useMotion();
  const variants = getVariant('modal');

  return (
    <motion.div
      variants={variants}
      initial="initial"
      animate="animate"
      exit="exit"
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
};

export interface MotionBackdropProps extends HTMLMotionProps<'div'> {
  children: React.ReactNode;
}

export const MotionBackdrop: React.FC<MotionBackdropProps> = ({
  children,
  className = '',
  ...props
}) => {
  const { isReducedMotion } = useMotion();
  const variants = isReducedMotion
    ? { initial: { opacity: 0 }, animate: { opacity: 1 }, exit: { opacity: 0 } }
    : backdropVariants;

  return (
    <motion.div
      variants={variants}
      initial="initial"
      animate="animate"
      exit="exit"
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
};

export interface StatusPulseProps {
  color?: 'emerald' | 'amber' | 'rose' | 'blue' | 'slate';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  label?: string;
}

export const StatusPulse: React.FC<StatusPulseProps> = ({
  color = 'emerald',
  size = 'md',
  className = '',
  label,
}) => {
  const { isReducedMotion } = useMotion();

  const colorMap = {
    emerald: 'bg-emerald-400',
    amber: 'bg-amber-400',
    rose: 'bg-rose-400',
    blue: 'bg-blue-400',
    slate: 'bg-slate-400',
  };

  const sizeMap = {
    sm: 'w-1.5 h-1.5',
    md: 'w-2 h-2',
    lg: 'w-2.5 h-2.5',
  };

  const dotClass = `${sizeMap[size]} rounded-full ${colorMap[color]} ${
    !isReducedMotion ? 'animate-pulse' : ''
  } ${className}`;

  return (
    <span className="inline-flex items-center gap-1.5" aria-hidden={label ? undefined : 'true'}>
      <span className={dotClass} />
      {label && <span className="sr-only">{label}</span>}
    </span>
  );
};
