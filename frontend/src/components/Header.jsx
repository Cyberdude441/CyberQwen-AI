import React from 'react';
import { Shield, Cpu, Activity, Download, Trash2, Terminal } from 'lucide-react';

export default function Header({ status, device, totalTokens, onClearChat, onExportChat, conversationLength }) {
  return (
    <header className="h-16 border-b border-cyber-border bg-cyber-card/80 backdrop-blur-md px-6 flex items-center justify-between z-10">
      <div className="flex items-center gap-3">
        <div className="relative">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500/20 to-cyber-neon/20 border border-cyber-neon/40 flex items-center justify-center shadow-neon">
            <Shield className="w-5 h-5 text-cyber-neon animate-pulse" />
          </div>
          <span className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-cyber-neon rounded-full border-2 border-cyber-dark"></span>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold tracking-wider font-mono text-white flex items-center gap-1.5">
              CYBER<span className="text-cyber-cyan">QWEN</span>
              <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-sans font-semibold">8B-v3</span>
            </h1>
          </div>
          <p className="text-xs text-slate-400 font-mono">Offensive & Defensive AI Operations Suite</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* System Telemetry Pills */}
        <div className="hidden md:flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-dark/60 border border-cyber-border text-xs font-mono text-slate-300">
            <Activity className="w-3.5 h-3.5 text-cyber-neon" />
            <span>STATUS: <span className="text-cyber-neon font-bold">{status.toUpperCase()}</span></span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-dark/60 border border-cyber-border text-xs font-mono text-slate-300">
            <Cpu className="w-3.5 h-3.5 text-cyber-cyan" />
            <span>DEVICE: <span className="text-cyber-cyan font-bold">{device.toUpperCase()}</span></span>
          </div>

          {totalTokens > 0 && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyber-dark/60 border border-cyber-border text-xs font-mono text-slate-300">
              <Terminal className="w-3.5 h-3.5 text-purple-400" />
              <span>TOKENS: <span className="text-purple-400 font-bold">{totalTokens}</span></span>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 border-l border-cyber-border pl-4">
          <button
            onClick={onExportChat}
            disabled={conversationLength === 0}
            title="Export conversation as Markdown"
            className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-cyan-400 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4" />
          </button>
          
          <button
            onClick={onClearChat}
            disabled={conversationLength === 0}
            title="Clear active conversation"
            className="p-2 rounded-lg bg-slate-800/80 hover:bg-red-950/50 border border-slate-700 hover:border-red-800 text-slate-300 hover:text-red-400 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
}
