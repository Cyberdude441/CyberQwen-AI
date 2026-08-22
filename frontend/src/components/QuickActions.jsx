import React from 'react';
import { AlertTriangle, Code, FileText, Bug, Trophy } from 'lucide-react';

export default function QuickActions({ onSelectAction, disabled }) {
  const actions = [
    {
      id: 'vulnerability_analysis',
      label: 'Analyze Vulnerability',
      icon: AlertTriangle,
      color: 'text-red-400 border-red-500/30 hover:border-red-400 hover:bg-red-950/20'
    },
    {
      id: 'code_review',
      label: 'Review Code',
      icon: Code,
      color: 'text-cyan-400 border-cyan-500/30 hover:border-cyan-400 hover:bg-cyan-950/20'
    },
    {
      id: 'log_analysis',
      label: 'Analyze Log',
      icon: FileText,
      color: 'text-amber-400 border-amber-500/30 hover:border-amber-400 hover:bg-amber-950/20'
    },
    {
      id: 'cve_explainer',
      label: 'Explain CVE',
      icon: Bug,
      color: 'text-purple-400 border-purple-500/30 hover:border-purple-400 hover:bg-purple-950/20'
    },
    {
      id: 'ctf_assistant',
      label: 'CTF Assistant',
      icon: Trophy,
      color: 'text-emerald-400 border-emerald-500/30 hover:border-emerald-400 hover:bg-emerald-950/20'
    }
  ];

  return (
    <div className="flex items-center gap-2 overflow-x-auto py-2 px-1 no-scrollbar">
      <span className="text-xs font-mono text-slate-500 font-semibold uppercase tracking-wider pl-1">Actions:</span>
      {actions.map((act) => {
        const Icon = act.icon;
        return (
          <button
            key={act.id}
            onClick={() => onSelectAction(act.id)}
            disabled={disabled}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border bg-cyber-card/60 backdrop-blur-sm text-xs font-mono transition-all duration-200 whitespace-nowrap disabled:opacity-50 disabled:cursor-not-allowed ${act.color}`}
          >
            <Icon className="w-3.5 h-3.5" />
            <span>[{act.label}]</span>
          </button>
        );
      })}
    </div>
  );
}
