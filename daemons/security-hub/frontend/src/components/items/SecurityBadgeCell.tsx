import type React from 'react';
import type { ManagedItem } from '../../types';

interface SecurityBadgeCellProps {
  item: ManagedItem;
  onOpenBrokenLinkage: (pkgName: string, details: string) => void;
}

const LINKAGE_BTN_CLASS =
  'badge crit cursor-pointer border-red-500/45 hover:bg-red-500/28 hover:border-red-500 hover:text-white hover:-translate-y-px transition-all';

/**
 * Renders CVE counts and interactive Broken Linkage diagnostic badges for a managed item.
 */
export const SecurityBadgeCell: React.FC<SecurityBadgeCellProps> = ({
  item,
  onOpenBrokenLinkage,
}) => {
  const detailsText = item.linkage_details || 'Missing shared library dependency';
  const hasHighOrCrit = item.crit_count > 0 || item.high_count > 0;

  if (item.broken_linkage && hasHighOrCrit) {
    return (
      <div className="flex flex-col gap-1 items-start">
        <button
          type="button"
          className={LINKAGE_BTN_CLASS}
          onClick={() => onOpenBrokenLinkage(item.name, detailsText)}
        >
          ⚠ Broken Linkage (Details)
        </button>
        <span className="badge crit">
          ● {item.crit_count} Crit / {item.high_count} High
        </span>
      </div>
    );
  }

  if (item.broken_linkage) {
    return (
      <button
        type="button"
        className={LINKAGE_BTN_CLASS}
        title="Click to view broken linkage details"
        onClick={() => onOpenBrokenLinkage(item.name, detailsText)}
      >
        ⚠ Broken Linkage (Details)
      </button>
    );
  }

  if (hasHighOrCrit) {
    const firstId = item.vulnerabilities?.[0]?.id || 'CVE';
    return (
      <span className="badge crit">
        ● {item.crit_count} Crit / {item.high_count} High ({firstId})
      </span>
    );
  }

  return <span className="badge ok">✓ 0 CVEs</span>;
};
