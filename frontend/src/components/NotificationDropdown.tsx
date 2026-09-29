import React, { useRef, useEffect } from 'react';
import { Bell, AlertTriangle, CheckCircle, Clock, Zap, X } from 'lucide-react';
import { Notification } from '@devsecops/shared/types';
import { formatDistanceToNow } from 'date-fns';

interface NotificationDropdownProps {
  notifications: Notification[];
  unreadCount: number;
  onMarkRead: (id: string) => void;
  onMarkAllRead: () => void;
}

export function NotificationDropdown({
  notifications,
  unreadCount,
  onMarkRead,
  onMarkAllRead
}: NotificationDropdownProps) {
  const [open, setOpen] = React.useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const getIcon = (type: Notification['type']) => {
    switch (type) {
      case 'vulnerability_found':
        return <AlertTriangle className="w-5 h-5 text-severity-critical" />;
      case 'scan_complete':
      case 'job_completed':
      case 'fix_ready':
        return <CheckCircle className="w-5 h-5 text-accent-green" />;
      case 'scan_failed':
      case 'job_failed':
        return <AlertTriangle className="w-5 h-5 text-severity-high" />;
      case 'pr_created':
        return <Zap className="w-5 h-5 text-accent-purple" />;
      default:
        return <Clock className="w-5 h-5 text-foreground-muted" />;
    }
  };

  const getSeverityColor = (type: Notification['type']) => {
    if (['vulnerability_found', 'scan_failed', 'job_failed'].includes(type)) return 'text-severity-critical';
    if (['scan_complete', 'job_completed', 'fix_ready', 'pr_created'].includes(type)) return 'text-accent-green';
    return 'text-foreground-muted';
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        className="btn-icon text-foreground-secondary hover:text-foreground relative"
        onClick={() => setOpen(!open)}
        aria-label={`Notifications${unreadCount > 0 ? `, ${unreadCount} unread` : ''}`}
        aria-expanded={open}
      >
        <Bell className="w-5 h-5" />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 w-5 h-5 bg-severity-critical text-white text-xs font-medium rounded-full flex items-center justify-center">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="dropdown w-80 sm:w-96">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <h3 className="font-semibold text-foreground">Notifications</h3>
            <div className="flex items-center gap-2">
              {unreadCount > 0 && (
                <button
                  className="text-xs text-accent-blue hover:underline"
                  onClick={onMarkAllRead}
                >
                  Mark all read
                </button>
              )}
              <button
                className="btn-icon p-1 text-foreground-secondary hover:text-foreground"
                onClick={() => setOpen(false)}
                aria-label="Close notifications"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="max-h-96 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="p-8 text-center text-foreground-muted">
                <Bell className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No notifications yet</p>
              </div>
            ) : (
              notifications.map((notification) => (
                <button
                  key={notification.id}
                  className={`w-full text-left px-4 py-3 hover:bg-background-tertiary transition-colors ${
                    !notification.read ? 'bg-background-tertiary/50' : ''
                  }`}
                  onClick={() => {
                    if (!notification.read) onMarkRead(notification.id);
                    if (notification.actionUrl) window.location.href = notification.actionUrl;
                    setOpen(false);
                  }}
                >
                  <div className="flex gap-3">
                    <div className={`flex-shrink-0 ${getSeverityColor(notification.type)}`}>
                      {getIcon(notification.type)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between gap-2">
                        <p className="font-medium text-foreground text-sm">{notification.title}</p>
                        <span className="text-xs text-foreground-muted whitespace-nowrap">
                          {formatDistanceToNow(new Date(notification.createdAt), { addSuffix: true })}
                        </span>
                      </div>
                      <p className="text-sm text-foreground-secondary mt-1 line-clamp-2">{notification.message}</p>
                      {!notification.read && (
                        <span className="inline-block mt-1.5 w-1.5 h-1.5 rounded-full bg-accent-blue" />
                      )}
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>

          {notifications.length > 0 && (
            <div className="px-4 py-3 border-t border-border">
              <button className="w-full text-center text-sm text-accent-blue hover:underline">
                View all notifications
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}