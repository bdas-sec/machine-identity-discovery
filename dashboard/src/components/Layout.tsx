import { Outlet, NavLink } from 'react-router-dom';
import {
  Shield,
  Activity,
  Terminal,
  Grid3x3,
  Monitor,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { useWebSocket } from '@/hooks/useWebSocket';

const navItems = [
  { to: '/', icon: Monitor, label: 'Demo Mode' },
  { to: '/interactive', icon: Activity, label: 'Interactive' },
  { to: '/scenarios', icon: Terminal, label: 'Scenarios' },
  { to: '/mitre', icon: Grid3x3, label: 'MITRE Map' },
];

export default function Layout() {
  const { connected, reconnecting } = useWebSocket();

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-950 border-r border-gray-800 flex flex-col shrink-0">
        {/* Branding */}
        <div className="p-5 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-nhi-500/20 border border-nhi-500/30 flex items-center justify-center">
              <Shield className="w-5 h-5 text-nhi-400" />
            </div>
            <div>
              <h1 className="text-sm font-bold text-white tracking-wide">
                NHI Security
              </h1>
              <p className="text-[10px] text-gray-500 uppercase tracking-widest">
                Attack Dashboard
              </p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-1">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 ${
                  isActive
                    ? 'bg-nhi-500/15 text-nhi-400 border-glow'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
                }`
              }
            >
              <Icon className="w-4 h-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Connection status */}
        <div className="p-4 border-t border-gray-800">
          <div className="flex items-center gap-2 text-xs">
            {connected ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-green-400" />
                <span className="text-green-400">Connected</span>
              </>
            ) : reconnecting ? (
              <>
                <WifiOff className="w-3.5 h-3.5 text-yellow-400 animate-pulse" />
                <span className="text-yellow-400">Reconnecting...</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5 text-red-400" />
                <span className="text-red-400">Disconnected</span>
              </>
            )}
          </div>
          <p className="text-[10px] text-gray-600 mt-1">v0.1.0</p>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto bg-gray-900">
        <Outlet />
      </main>
    </div>
  );
}
