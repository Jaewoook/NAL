import type React from 'react';
import { useEffect, useRef } from 'react';
import { cn } from '../lib/cn';
import { hubApi } from '../lib/http';
import type { RenderedLogEntry, Task } from '../types';
import { Badge, type BadgeTone } from './ui';

interface TaskLogsPanelProps {
  tasks: Task[];
  activeTaskId: string;
  logs: RenderedLogEntry[];
  onSelectTask: (taskId: string) => void;
}

function getStreamClass(stream?: string): string {
  if (stream === 'cmd') return 'text-sky-400 font-semibold';
  if (stream === 'error' || stream === 'stderr') return 'text-red-400';
  return 'text-slate-300';
}

function getTaskBadgeTone(status: string): BadgeTone {
  if (status === 'succeeded') return 'ok';
  if (status === 'rolled_back' || status === 'running') return 'warn';
  return 'crit';
}

function formatTaskSubtitle(task: Task): string {
  if (task.from_version || task.to_version) {
    return `(${task.from_version || ''} → ${task.to_version || ''})`;
  }
  return task.target_type ? `(${task.target_type})` : '';
}

/**
 * Displays recent task executions alongside an auto-scrolling live SSE log viewer.
 */
export const TaskLogsPanel: React.FC<TaskLogsPanelProps> = ({
  tasks,
  activeTaskId,
  logs,
  onSelectTask,
}) => {
  const terminalRef = useRef<HTMLDivElement | null>(null);
  const lastLogKey = logs[logs.length - 1]?.key;

  useEffect(() => {
    if (lastLogKey && terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [lastLogKey]);

  return (
    <div id="panel-logs">
      <div className="grid grid-cols-1 lg:grid-cols-[380px_1fr] gap-4.5">
        <div
          className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden"
          id="task-list-container"
        >
          {tasks.length === 0 ? (
            <div className="p-5 text-slate-400 text-[13px]">No tasks recorded yet.</div>
          ) : (
            tasks.map((task) => {
              const nodeLabel = task.node ? `[${task.node}] ` : '';
              const subDetail = formatTaskSubtitle(task);

              return (
                <button
                  type="button"
                  key={task.id}
                  aria-pressed={activeTaskId === task.id}
                  className={cn(
                    'w-full text-left bg-transparent border-0 border-b border-slate-700 px-3.5 py-3 cursor-pointer transition-colors hover:bg-surface-hover hover:border-l-[3px] hover:border-l-sky-400',
                    activeTaskId === task.id && 'bg-surface-hover border-l-[3px] border-l-sky-400'
                  )}
                  onClick={() => onSelectTask(task.id)}
                >
                  <div className="flex justify-between items-center gap-2">
                    <strong className="text-[13px] text-slate-50">
                      {task.id} · {nodeLabel}
                      {task.task_type}
                    </strong>
                    <Badge tone={getTaskBadgeTone(task.status)}>{task.status}</Badge>
                  </div>
                  <div className="text-xs text-slate-400 font-mono break-all mt-1">
                    {task.target_name}
                    {subDetail ? ` ${subDetail}` : ''}
                  </div>
                </button>
              );
            })
          )}
        </div>

        <div>
          <div className="bg-surface-bar border border-slate-700 border-b-0 rounded-t-[10px] px-4 py-2.5 flex justify-between items-center text-[12.5px]">
            <div id="active-task-title">
              {activeTaskId
                ? `Task ${activeTaskId} — Execution Output`
                : 'Select a task to view stdout/stderr logs'}
            </div>
            {activeTaskId && (
              <a
                id="download-log-link"
                className="btn btn-ghost inline-flex no-underline"
                href={hubApi.taskDownloadUrl(activeTaskId)}
                target="_blank"
                rel="noopener noreferrer"
              >
                ⬇ Download .log
              </a>
            )}
          </div>
          <div
            className="bg-surface-terminal border border-slate-700 rounded-b-[10px] font-mono text-[12.5px] leading-relaxed text-slate-200 p-4 h-[440px] overflow-y-auto"
            id="terminal-output"
            ref={terminalRef}
          >
            {logs.map((entry) =>
              entry.rawText ? (
                <div key={entry.key}>{entry.line}</div>
              ) : (
                <div key={entry.key}>
                  <span className="text-slate-500 mr-2">
                    [{entry.loggedAt ? new Date(entry.loggedAt).toLocaleTimeString() : ''}]
                  </span>{' '}
                  <span className={getStreamClass(entry.stream)}>
                    [{String(entry.stream || '').toUpperCase()}]
                  </span>{' '}
                  {entry.line}
                </div>
              )
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
