import { useRef, useEffect, useState } from 'react';
import { User, Settings, LogOut, Moon, Sun, Monitor } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { User as UserType } from '@devsecops/shared/types';

interface UserMenuProps {
  user: UserType | null;
  onLogout: () => void;
  onSettings: () => void;
}

export function UserMenu({ user, onLogout, onSettings }: UserMenuProps) {
  const [open, setOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const { theme, setTheme } = useTheme();

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        className="flex items-center gap-2 btn-icon p-1.5"
        onClick={() => setOpen(!open)}
        aria-label="User menu"
        aria-expanded={open}
      >
        {user?.avatarUrl ? (
          <img src={user.avatarUrl} alt="" className="w-8 h-8 rounded-full" />
        ) : (
          <div className="w-8 h-8 rounded-full bg-accent-blue/20 flex items-center justify-center">
            <User className="w-4 h-4 text-accent-blue" />
          </div>
        )}
      </button>

      {open && (
        <div className="dropdown w-56">
          <div className="px-4 py-3 border-b border-border">
            <div className="flex items-center gap-3">
              {user?.avatarUrl ? (
                <img src={user.avatarUrl} alt="" className="w-10 h-10 rounded-full" />
              ) : (
                <div className="w-10 h-10 rounded-full bg-accent-blue/20 flex items-center justify-center">
                  <span className="text-lg font-medium text-accent-blue">{user?.name?.[0].toUpperCase()}</span>
                </div>
              )}
              <div className="flex-1 min-w-0">
                <p className="font-medium text-foreground truncate">{user?.name}</p>
                <p className="text-xs text-foreground-muted truncate">{user?.email}</p>
                <span className={`badge ${user?.role === 'admin' ? 'badge-critical' : user?.role === 'engineer' ? 'badge-info' : 'badge-success'}`}>
                  {user?.role}
                </span>
              </div>
            </div>
          </div>

          <div className="py-1">
            <button
              className="dropdown-item"
              onClick={() => { onSettings(); setOpen(false); }}
            >
              <Settings className="w-4 h-4" />
              Settings
            </button>
            <div className="dropdown-divider" />
            <div className="px-4 py-2">
              <p className="text-xs font-medium text-foreground-secondary uppercase tracking-wider mb-2">Theme</p>
              <div className="grid grid-cols-3 gap-1">
                {['light', 'dark', 'system'].map((t) => (
                  <button
                    key={t}
                    className={`py-1.5 px-2 rounded text-xs font-medium transition-colors ${
                      theme === t
                        ? 'bg-accent-blue/20 text-accent-blue'
                        : 'text-foreground-secondary hover:text-foreground hover:bg-background-tertiary'
                    }`}
                    onClick={() => { setTheme(t as any); setOpen(false); }}
                  >
                    {t === 'light' && <Sun className="w-4 h-4 mx-auto mb-1" />}
                    {t === 'dark' && <Moon className="w-4 h-4 mx-auto mb-1" />}
                    {t === 'system' && <Monitor className="w-4 h-4 mx-auto mb-1" />}
                    <span className="block capitalize">{t}</span>
                  </button>
                ))}
              </div>
            </div>
            <div className="dropdown-divider" />
            <button
              className="dropdown-item text-severity-critical"
              onClick={onLogout}
            >
              <LogOut className="w-4 h-4" />
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}