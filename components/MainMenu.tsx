

import React from 'react';
import { BrainIcon, ShieldExclamationIcon, CodeBracketSquareIcon, RssIcon, BriefcaseIcon, FingerPrintIcon } from './icons';
import { useLocalization } from '../contexts/LocalizationContext';

export type View = 'ai_analyst' | 'vt_scanner' | 'casebook' | 'ua_analyzer';

interface MenuItem {
  id: View | string;
  labelKey: string;
  Icon: React.FC<{ className?: string }>;
  enabled: boolean;
}

const MainMenu: React.FC<{ activeView: View; setActiveView: (view: View) => void; }> = ({ activeView, setActiveView }) => {
  const { t } = useLocalization();

  const menuItems: MenuItem[] = [
    { id: 'casebook', labelKey: 'casebook', Icon: BriefcaseIcon, enabled: true },
    { id: 'ai_analyst', labelKey: 'newInvestigation', Icon: BrainIcon, enabled: true },
    { id: 'vt_scanner', labelKey: 'vtScanner', Icon: ShieldExclamationIcon, enabled: true },
    { id: 'ua_analyzer', labelKey: 'uaAnalyzer', Icon: FingerPrintIcon, enabled: true },
    { id: 'vuln_scanner', labelKey: 'vulnScanner', Icon: CodeBracketSquareIcon, enabled: false },
    { id: 'threat_intel', labelKey: 'threatIntel', Icon: RssIcon, enabled: false },
  ];

  const getButtonClass = (item: MenuItem) => {
    const baseClass = 'flex-1 group flex flex-col sm:flex-row items-center justify-center gap-2 sm:gap-3 px-4 py-3 text-sm font-medium transition-all duration-200 ease-in-out transform';
    if (item.enabled) {
      if (item.id === activeView) {
        return `${baseClass} bg-sentinel-gray-medium text-sentinel-blue scale-105 shadow-lg border-b-2 border-sentinel-blue`;
      }
      return `${baseClass} text-gray-400 hover:bg-sentinel-gray-light/50 hover:text-white hover:scale-105`;
    }
    return `${baseClass} text-gray-500 cursor-not-allowed opacity-60`;
  };

  return (
    <div className="bg-sentinel-gray-medium/70 rounded-xl shadow-lg border border-sentinel-gray-light flex overflow-hidden">
      {menuItems.map(item => (
        <button
          key={item.id}
          onClick={() => item.enabled && setActiveView(item.id as View)}
          className={getButtonClass(item)}
          disabled={!item.enabled}
          aria-disabled={!item.enabled}
          aria-current={item.id === activeView ? 'page' : undefined}
        >
          <item.Icon className={`h-5 w-5 sm:h-6 sm:w-6 transition-colors ${item.id === activeView ? 'text-sentinel-blue' : 'text-gray-500 group-hover:text-white'}`} />
          <span className="flex items-center">
            {t(item.labelKey)}
            {!item.enabled && (
                <span className="ms-2 text-xs bg-sentinel-gray-dark text-gray-400 px-2 py-0.5 rounded-full">
                    {t('soon')}
                </span>
            )}
          </span>
        </button>
      ))}
    </div>
  );
};

export default MainMenu;
