"use client";

import React from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

export const BackgroundBeams = ({ className }: { className?: string }) => {
  return (
    <div
      className={cn(
        "absolute inset-0 overflow-hidden pointer-events-none [mask-image:radial-gradient(ellipse_at_center,white,transparent)]",
        className
      )}
    >
      {/* Subtle grid background */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f293708_1px,transparent_1px),linear-gradient(to_bottom,#1f293708_1px,transparent_1px)] bg-[size:32px_32px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)]" />

      {/* Ambient scanning beam */}
      <motion.div
        initial={{ opacity: 0.1, y: -200 }}
        animate={{
          opacity: [0.1, 0.25, 0.1],
          y: ["-10%", "110%"],
        }}
        transition={{
          duration: 10,
          repeat: Infinity,
          ease: "linear",
        }}
        className="absolute left-0 right-0 h-40 bg-gradient-to-b from-transparent via-cyan-500/10 to-transparent blur-xl"
      />
    </div>
  );
};
