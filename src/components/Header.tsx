import React from 'react';
import {
  ShieldAlert,
  Terminal,
  Activity,
  Layers,
  Globe2,
  Share2,
  FileText,
  Sliders,
  UserCheck,
  Radio,
  FileSearch,
} from 'lucide-react';
import { UserProfile, UserRole } from '../types';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  currentUser: UserProfile | null;
  onSwitchRole: (role: UserRole) => void;
  stats?: any;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  currentUser,
  onSwitchRole,
  stats,
}) => {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: Activity },
    { id: 'ingest', label: 'Ingest & Analyze', icon: Terminal, highlight: true },
    { id: 'cases', label: 'Case Files', icon: Layers, badge: stats?.total_cases },
    { id: 'geomap', label: 'Global Relay Map', icon: Globe2 },
    { id: 'graph', label: 'Threat Graph', icon: Share2 },
    { id: 'audit', label: 'Audit Trail', icon: FileText },
    { id: 'settings', label: 'Adapters & Intel', icon: Sliders },
  ];

  return (
    <header id="main-header" className="bg-neutral-950/90 backdrop-blur-md border-b border-neutral-800/80 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & Platform Identity */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
            <div className="h-10 w-10 rounded-lg bg-gradient-to-br from-indigo-500 via-indigo-600 to-purple-700 flex items-center justify-center shadow-lg shadow-indigo-500/20 border border-indigo-400/30">
              <ShieldAlert className="h-5 w-5 text-white animate-pulse" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg tracking-tight text-white font-mono">CANNON<span className="text-indigo-400">CREW</span></span>
                <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-indigo-950/80 border border-indigo-500/30 text-indigo-300 font-mono">
                  SIH 2026
                </span>
              </div>
              <p className="text-xs text-neutral-400 hidden sm:block">Email Threat Forensics & Intelligence</p>
            </div>
          </div>

          {/* Center Navigation Links */}
          <nav className="hidden lg:flex items-center space-x-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  id={`nav-${item.id}`}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-neutral-800 text-white border border-neutral-700 shadow-sm'
                      : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900'
                  }`}
                >
                  <Icon className={`h-4 w-4 ${isActive ? 'text-indigo-400' : 'text-neutral-400'}`} />
                  <span>{item.label}</span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-neutral-800 text-neutral-300 border border-neutral-700">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Right Action: Role Selector & System Status */}
          <div className="flex items-center space-x-3">
            {/* Live System Indicator */}
            <div className="hidden md:flex items-center space-x-2 px-2.5 py-1 rounded-full bg-neutral-900 border border-neutral-800 text-xs">
              <Radio className="h-3 w-3 text-emerald-400 animate-pulse" />
              <span className="text-neutral-300 font-mono text-[11px]">SOC LIVE</span>
            </div>

            {/* Role Switcher Pill */}
            <div className="flex items-center bg-neutral-900 rounded-lg p-1 border border-neutral-800">
              <span className="text-[11px] font-semibold text-neutral-400 px-2 flex items-center gap-1">
                <UserCheck className="h-3 w-3 text-indigo-400" />
                Role:
              </span>
              {(['ADMIN', 'ANALYST', 'VIEWER'] as UserRole[]).map((r) => (
                <button
                  key={r}
                  id={`role-btn-${r}`}
                  onClick={() => onSwitchRole(r)}
                  className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold transition-colors ${
                    currentUser?.role === r
                      ? r === 'ADMIN'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                        : r === 'ANALYST'
                        ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40'
                        : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'text-neutral-400 hover:text-neutral-200'
                  }`}
                  title={`Switch to ${r} role`}
                >
                  {r}
                </button>
              ))}
            </div>
          </div>

        </div>

        {/* Mobile Sub-Navigation */}
        <div className="lg:hidden flex items-center space-x-1 overflow-x-auto py-2 border-t border-neutral-800 scrollbar-none">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-colors ${
                  isActive
                    ? 'bg-neutral-800 text-white border border-neutral-700'
                    : 'text-neutral-400 hover:text-neutral-200'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>

      </div>
    </header>
  );
};
