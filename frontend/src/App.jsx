import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import ChatMessage from './components/ChatMessage';
import QuickActions from './components/QuickActions';
import FileUploadModal from './components/FileUploadModal';
import { Send, Upload, FolderArchive, Loader2, Check, Network, ShieldCheck } from 'lucide-react';

const API_BASE = 'http://localhost:8000';

export default function App() {
  const [messages, setMessages] = useState(() => {
    const saved = localStorage.getItem('cyberqwen_chat_history');
    if (saved) {
      try { return JSON.parse(saved); } catch (e) { }
    }
    return [
      {
        role: 'assistant',
        content: `### Welcome to CyberQwen Multi-Agent System (8B-v3)\n\nI am connected to a collaborative intelligence pipeline:\n- 🖥️ **CyberQwen 8B Local**: Primary cybersecurity domain model.\n- 🧠 **NVIDIA Nemotron**: Deep hypothesis formulation & solver planning.\n- 🛡️ **Google Gemini**: Adversarial verification & hallucination guard.\n\n*Upload a .zip challenge or select a pipeline above to begin.*`
      }
    ];
  });

  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [selectedModel, setSelectedModel] = useState('hybrid');
  const [analysisProgress, setAnalysisProgress] = useState(null);
  const [systemStatus, setSystemStatus] = useState('checking');
  const [device, setDevice] = useState('detecting');
  const [totalTokens, setTotalTokens] = useState(0);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    localStorage.setItem('cyberqwen_chat_history', JSON.stringify(messages));
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, analysisProgress]);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const checkHealth = async () => {
    try {
      const res = await fetch(`${API_BASE}/health`);
      if (res.ok) {
        const data = await res.json();
        setSystemStatus(data.status || 'online');
        setDevice(data.device || 'CPU');
      } else {
        setSystemStatus('offline');
      }
    } catch (e) {
      setSystemStatus('offline');
    }
  };

  const handleSendMessage = async (textToSend = input) => {
    const messageContent = textToSend.trim();
    if (!messageContent || isLoading) return;

    const userMessage = { role: 'user', content: messageContent };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const historyPayload = messages.slice(1).map((m) => ({ role: m.role, content: m.content }));

      const res = await fetch(`${API_BASE}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: messageContent,
          history: historyPayload,
          mode: selectedModel,
          temperature: 0.7,
          max_tokens: 1200
        })
      });

      if (!res.ok) throw new Error(`API returned HTTP ${res.status}`);

      const data = await res.json();
      const botMessage = {
        role: 'assistant',
        content: data.response || 'No response returned from model.',
        latency_ms: data.latency_ms,
        tokens: data.tokens
      };

      if (data.tokens) setTotalTokens((prev) => prev + data.tokens);
      setMessages((prev) => [...prev, botMessage]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `⚠️ **Connection Error**: Unable to reach CyberQwen backend at \`${API_BASE}\`. Ensure FastAPI is running on port 8000.\n\n*Details: ${err.message}*`
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectQuickAction = (actionId) => {
    const promptMap = {
      vulnerability_analysis: "Perform an in-depth vulnerability analysis on the following system configuration / code snippet:\n\n",
      code_review: "Review the following source code against OWASP Top 10 vulnerabilities and suggest secure remediations:\n\n",
      log_analysis: "Inspect the following log stream for intrusion indicators, unauthorized access, or anomalies:\n\n",
      cve_explainer: "Explain the technical root cause, CVSS score impact, and vendor patch mitigation for CVE: ",
      ctf_assistant: "Analyze this CTF challenge problem and provide a step-by-step strategy with Python exploit code:\n\n"
    };
    setInput(promptMap[actionId] || "");
  };

  const handleFileUpload = async (file, action, mode, customPrompt) => {
    setIsUploadOpen(false);
    setIsLoading(true);

    setAnalysisProgress({
      fileName: file.name,
      fileSize: (file.size / 1024).toFixed(1) + ' KB',
      mode: mode || selectedModel,
      steps: [
        { label: 'File received & unpacked', status: 'done' },
        { label: 'Artifacts scanned & indexed', status: 'done' },
        { label: 'Nemotron reasoning dispatched', status: 'running' },
        { label: 'Gemini verification checking', status: 'pending' },
        { label: 'CyberQwen consensus synthesis', status: 'pending' }
      ]
    });

    const userMessage = {
      role: 'user',
      content: `📁 **Uploaded Target**: \`${file.name}\` (${(file.size / 1024).toFixed(1)} KB)\n**Action**: \`${action}\` | **Pipeline**: \`${(mode || selectedModel).toUpperCase()}\`${customPrompt ? `\n**Directive**: ${customPrompt}` : ''}`
    };
    setMessages((prev) => [...prev, userMessage]);

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('action', action);
      formData.append('mode', mode || selectedModel);
      if (customPrompt) formData.append('custom_prompt', customPrompt);

      setTimeout(() => {
        setAnalysisProgress((prev) => prev ? ({
          ...prev,
          steps: [
            { label: 'File received & unpacked', status: 'done' },
            { label: 'Artifacts scanned & indexed', status: 'done' },
            { label: 'Nemotron reasoning dispatched', status: 'done' },
            { label: 'Gemini verification checking', status: 'done' },
            { label: 'CyberQwen consensus synthesis', status: 'running' }
          ]
        }) : null);
      }, 800);

      const res = await fetch(`${API_BASE}/upload`, {
        method: 'POST',
        body: formData
      });

      if (!res.ok) throw new Error(`Upload returned status ${res.status}`);

      const data = await res.json();

      let consensusBadge = '';
      if (data.consensus) {
        consensusBadge = data.consensus === 'verified'
          ? `> [!NOTE]\n> **Multi-Model Consensus: VERIFIED** (CyberQwen + Nemotron + Gemini aligned)\n\n`
          : `> [!WARNING]\n> **Multi-Model Consensus: UNVERIFIED** (Insufficient evidence for complete flag recovery)\n\n`;
      }

      const botMessage = {
        role: 'assistant',
        content: consensusBadge + data.response,
        latency_ms: data.latency_ms,
        tokens: data.tokens
      };

      if (data.tokens) setTotalTokens((prev) => prev + data.tokens);
      setMessages((prev) => [...prev, botMessage]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: `⚠️ **Upload Error**: Failed to process file \`${file.name}\`. ${err.message}`
        }
      ]);
    } finally {
      setIsLoading(false);
      setAnalysisProgress(null);
    }
  };

  const handleClearChat = () => {
    setMessages([
      {
        role: 'assistant',
        content: 'Session cleared. Ready for new cybersecurity operational queries.'
      }
    ]);
    setTotalTokens(0);
    localStorage.removeItem('cyberqwen_chat_history');
  };

  const handleExportChat = () => {
    const mdContent = messages
      .map((m) => `### ${m.role === 'user' ? 'Operator' : 'CyberQwen AI'}\n\n${m.content}\n`)
      .join('\n---\n\n');

    const blob = new Blob([mdContent], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `CyberQwen_Session_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.md`;
    link.click();
  };

  return (
    <div className="flex flex-col h-screen bg-[#080c14] text-slate-100 font-sans">
      <Header
        status={systemStatus}
        device={device}
        totalTokens={totalTokens}
        onClearChat={handleClearChat}
        onExportChat={handleExportChat}
        conversationLength={messages.length}
        selectedModel={selectedModel}
        onSelectModel={setSelectedModel}
      />

      <div className="flex-1 overflow-y-auto overflow-x-hidden">
        {messages.map((msg, idx) => (
          <ChatMessage key={idx} message={msg} />
        ))}

        {/* Multi-Model Progress Card */}
        {analysisProgress && (
          <div className="py-5 px-6 bg-cyan-950/30 border-y border-cyber-cyan/40 backdrop-blur-md">
            <div className="max-w-4xl mx-auto space-y-3">
              <div className="flex items-center gap-2 text-cyber-cyan font-mono text-xs font-bold uppercase tracking-wider">
                <Network className="w-4 h-4 animate-pulse text-cyber-neon" />
                <span>Multi-Model Reasoning Pipeline: <span className="text-white">{analysisProgress.fileName}</span> ({analysisProgress.mode.toUpperCase()})</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-2">
                {analysisProgress.steps.map((st, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs font-mono px-3 py-2 rounded-lg bg-cyber-dark/80 border border-cyber-border">
                    {st.status === 'done' && <Check className="w-3.5 h-3.5 text-cyber-neon flex-shrink-0" />}
                    {st.status === 'running' && <Loader2 className="w-3.5 h-3.5 text-cyber-cyan animate-spin flex-shrink-0" />}
                    {st.status === 'pending' && <span className="w-3.5 h-3.5 rounded-full border border-slate-600 inline-block flex-shrink-0"></span>}
                    <span className={st.status === 'done' ? 'text-slate-200' : (st.status === 'running' ? 'text-cyber-cyan font-semibold' : 'text-slate-500')}>
                      {st.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {isLoading && !analysisProgress && (
          <div className="py-5 px-6 bg-cyber-card/60 border-b border-cyber-border">
            <div className="max-w-4xl mx-auto flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-cyan-950/60 border border-cyber-neon/40 flex items-center justify-center text-cyber-neon">
                <Loader2 className="w-4 h-4 animate-spin text-cyber-cyan" />
              </div>
              <span className="text-xs font-mono text-cyber-cyan animate-pulse">
                CyberQwen analyzing security mechanics & synthesizing response...
              </span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <div className="border-t border-cyber-border bg-[#0a0d16]/95 backdrop-blur-md p-4">
        <div className="max-w-4xl mx-auto space-y-2.5">
          <QuickActions onSelectAction={handleSelectQuickAction} disabled={isLoading} />

          <div className="relative flex items-center gap-2">
            <button
              onClick={() => setIsUploadOpen(true)}
              disabled={isLoading}
              title="Upload file or ZIP archive for analysis"
              className="p-3 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-cyan-400 transition-all disabled:opacity-50 shadow-sm"
            >
              <Upload className="w-5 h-5" />
            </button>

            <div className="relative flex-1">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSendMessage();
                  }
                }}
                placeholder="Ask CyberQwen about CVEs, CTF challenges, ROP chains, or upload a .zip archive..."
                rows={1}
                disabled={isLoading}
                className="w-full px-4 py-3 rounded-xl bg-cyber-dark/90 border border-slate-700 focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan text-sm text-slate-100 font-mono placeholder:text-slate-500 resize-none transition-all outline-none"
              />
            </div>

            <button
              onClick={() => handleSendMessage()}
              disabled={!input.trim() || isLoading}
              className="p-3 rounded-xl bg-gradient-to-tr from-cyan-500 to-cyber-neon hover:opacity-90 text-cyber-dark font-bold transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-neon"
            >
              <Send className="w-5 h-5" />
            </button>
          </div>

          <div className="flex justify-between items-center px-1 text-[11px] font-mono text-slate-500">
            <span>Press <kbd className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">Enter</kbd> to send, <kbd className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">Shift+Enter</kbd> for newline</span>
            <span>API: {API_BASE}</span>
          </div>
        </div>
      </div>

      <FileUploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUpload={handleFileUpload}
        isLoading={isLoading}
        selectedModel={selectedModel}
      />
    </div>
  );
}
