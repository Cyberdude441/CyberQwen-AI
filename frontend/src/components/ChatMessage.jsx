import React, { useState } from 'react';
import { User, Shield, Copy, Check, Clock, Cpu } from 'lucide-react';

export default function ChatMessage({ message }) {
  const [copied, setCopied] = useState(false);
  const isUser = message.role === 'user';

  const copyContent = () => {
    navigator.clipboard.writeText(message.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Simple Markdown formatter for bold, code blocks, bullet points, headers
  const renderFormattedText = (text) => {
    const lines = text.split('\n');
    let inCodeBlock = false;
    let codeLanguage = '';
    let codeBuffer = [];
    const elements = [];

    lines.forEach((line, idx) => {
      if (line.startsWith('```')) {
        if (inCodeBlock) {
          elements.push(
            <div key={`code-${idx}`} className="my-3 rounded-lg overflow-hidden border border-cyber-border bg-[#05070d]">
              <div className="bg-[#0e1320] px-4 py-1.5 text-[11px] font-mono text-cyan-400 border-b border-cyber-border flex justify-between items-center">
                <span>{codeLanguage || 'CODE'}</span>
                <span className="text-slate-500 text-[10px]">CyberQwen Sandbox</span>
              </div>
              <pre className="p-4 text-xs font-mono text-emerald-400 overflow-x-auto leading-relaxed">
                <code>{codeBuffer.join('\n')}</code>
              </pre>
            </div>
          );
          codeBuffer = [];
          inCodeBlock = false;
        } else {
          inCodeBlock = true;
          codeLanguage = line.replace('```', '').trim();
        }
        return;
      }

      if (inCodeBlock) {
        codeBuffer.push(line);
        return;
      }

      // Headers
      if (line.startsWith('### ')) {
        elements.push(<h3 key={idx} className="text-base font-bold text-cyan-300 mt-3 mb-1 font-mono">{line.replace('### ', '')}</h3>);
        return;
      }
      if (line.startsWith('#### ')) {
        elements.push(<h4 key={idx} className="text-sm font-semibold text-cyber-neon mt-2.5 mb-1 font-mono">{line.replace('#### ', '')}</h4>);
        return;
      }

      // Bullet points
      if (line.startsWith('- ') || line.startsWith('* ')) {
        const itemText = line.substring(2);
        elements.push(
          <li key={idx} className="text-slate-300 ml-4 list-disc text-sm my-0.5 leading-relaxed">
            {formatInlineTokens(itemText)}
          </li>
        );
        return;
      }

      // Standard text
      if (line.trim()) {
        elements.push(
          <p key={idx} className="text-slate-200 text-sm my-1.5 leading-relaxed font-sans">
            {formatInlineTokens(line)}
          </p>
        );
      } else {
        elements.push(<div key={idx} className="h-1.5"></div>);
      }
    });

    return elements;
  };

  const formatInlineTokens = (text) => {
    // Process bold (**text**) and code (`text`)
    const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
    return parts.map((part, i) => {
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={i} className="px-1.5 py-0.5 bg-cyan-950/60 text-cyan-300 border border-cyan-800/60 rounded text-xs font-mono">{part.slice(1, -1)}</code>;
      }
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={i} className="text-white font-semibold">{part.slice(2, -2)}</strong>;
      }
      return part;
    });
  };

  return (
    <div className={`py-4 px-6 transition-all ${isUser ? 'bg-cyber-dark/40 border-b border-cyber-border/40' : 'bg-cyber-card/60 border-b border-cyber-border'}`}>
      <div className="max-w-4xl mx-auto flex gap-4">
        {/* Avatar */}
        <div className="flex-shrink-0">
          {isUser ? (
            <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300">
              <User className="w-4 h-4" />
            </div>
          ) : (
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500/30 to-cyber-neon/30 border border-cyber-neon/50 flex items-center justify-center text-cyber-neon shadow-neon">
              <Shield className="w-4 h-4" />
            </div>
          )}
        </div>

        {/* Content */}
        <div className="flex-grow min-w-0">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-mono font-semibold tracking-wider text-slate-400">
              {isUser ? 'OPERATOR' : 'CYBERQWEN AI'}
            </span>
            <div className="flex items-center gap-3">
              {message.latency_ms && (
                <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1">
                  <Clock className="w-3 h-3 text-cyan-500" />
                  {message.latency_ms}ms
                </span>
              )}
              {message.tokens && (
                <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1">
                  <Cpu className="w-3 h-3 text-purple-400" />
                  {message.tokens} tokens
                </span>
              )}
              <button
                onClick={copyContent}
                className="p-1 rounded text-slate-500 hover:text-cyan-400 transition-colors"
                title="Copy message"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          <div className="prose prose-invert max-w-none">
            {renderFormattedText(message.content)}
          </div>
        </div>
      </div>
    </div>
  );
}
