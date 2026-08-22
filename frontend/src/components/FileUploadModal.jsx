import React, { useState, useRef } from 'react';
import { X, UploadCloud, FolderArchive, CheckCircle2, Loader2, Network } from 'lucide-react';

export default function FileUploadModal({ isOpen, onClose, onUpload, isLoading, selectedModel }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [action, setAction] = useState('ctf_assistant');
  const [mode, setMode] = useState(selectedModel || 'hybrid');
  const [customPrompt, setCustomPrompt] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);

  if (!isOpen) return null;

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!selectedFile) return;
    onUpload(selectedFile, action, mode, customPrompt);
  };

  const isZip = selectedFile?.name?.toLowerCase().endsWith('.zip');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-md p-4">
      <div className="w-full max-w-lg rounded-2xl glass-panel border border-cyber-border shadow-cyber-card overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-cyber-border bg-cyber-dark/60">
          <div className="flex items-center gap-2">
            <FolderArchive className="w-5 h-5 text-cyber-neon" />
            <h2 className="text-base font-bold font-mono text-white">Upload Target Evidence / Archive</h2>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {/* Drag & Drop Area */}
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all ${
              dragOver ? 'border-cyber-cyan bg-cyan-950/20' : 'border-slate-700 bg-cyber-dark/40 hover:border-slate-500'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              className="hidden"
              accept=".zip,.txt,.pdf,.json,.csv,.py,.c,.cpp,.h,.java,.js,.ts,.html,.css,.log,.md,.yaml,.yml,.sh,.ps1,.yar"
            />
            {selectedFile ? (
              <div className="flex flex-col items-center gap-2 text-cyber-cyan">
                <CheckCircle2 className="w-8 h-8 text-cyber-neon" />
                <span className="font-mono text-sm font-semibold text-white">{selectedFile.name}</span>
                <span className="text-xs text-slate-400 font-mono">
                  {(selectedFile.size / 1024).toFixed(1)} KB {isZip ? '• ZIP Archive (Auto-Extraction)' : '• Target File'}
                </span>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-2 text-slate-400">
                <UploadCloud className="w-8 h-8 text-slate-500" />
                <span className="text-sm font-medium text-slate-300">Drop CTF Challenge (.zip) or Source File</span>
                <span className="text-xs text-slate-500 font-mono">Supports .zip, .py, .c, .js, .json, .log, .pdf, etc.</span>
              </div>
            )}
          </div>

          {/* Model Pipeline Selection */}
          <div>
            <label className="block text-xs font-mono font-semibold text-slate-300 mb-1.5 uppercase flex items-center gap-1.5">
              <Network className="w-3.5 h-3.5 text-cyber-cyan" />
              Reasoning & Verification Pipeline
            </label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-cyber-dark/80 border border-slate-700 text-sm text-cyber-neon font-mono focus:outline-none focus:border-cyber-cyan"
            >
              <option value="hybrid">⚡ Hybrid Mode (CyberQwen + Nemotron + Gemini Consensus)</option>
              <option value="local">🖥️ CyberQwen Local Model Only</option>
              <option value="nemotron">🧠 NVIDIA Nemotron Reasoning Agent</option>
              <option value="gemini">🛡️ Google Gemini Verification Agent</option>
            </select>
          </div>

          {/* Analysis Goal */}
          <div>
            <label className="block text-xs font-mono font-semibold text-slate-300 mb-1.5 uppercase">
              Operational Objective
            </label>
            <select
              value={action}
              onChange={(e) => setAction(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-cyber-dark/80 border border-slate-700 text-sm text-slate-200 font-mono focus:outline-none focus:border-cyber-cyan"
            >
              <option value="ctf_assistant">🏆 CTF Challenge Solver (Extract & Recover Exact Flag)</option>
              <option value="vulnerability_analysis">🛡️ Comprehensive Vulnerability Assessment</option>
              <option value="code_review">🔍 Secure Code Review (OWASP Top 10 / CWE)</option>
              <option value="log_analysis">📊 Security Log & IoC Incident Analysis</option>
              <option value="cve_explainer">🐛 CVE & Exploit Root Cause Breakdown</option>
            </select>
          </div>

          {/* Optional Directives */}
          <div>
            <label className="block text-xs font-mono font-semibold text-slate-300 mb-1.5 uppercase">
              Custom Operator Directives (Optional)
            </label>
            <input
              type="text"
              placeholder="e.g. Focus on memory corruption, crack XOR key, or inspect stego"
              value={customPrompt}
              onChange={(e) => setCustomPrompt(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-cyber-dark/80 border border-slate-700 text-sm text-slate-200 font-mono focus:outline-none focus:border-cyber-cyan"
            />
          </div>

          {/* Submit Button */}
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm font-mono text-slate-300 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!selectedFile || isLoading}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-cyber-neon text-cyber-dark font-bold font-mono text-sm hover:opacity-90 transition-all disabled:opacity-50 shadow-neon"
            >
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Run Collaborative Analysis'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
