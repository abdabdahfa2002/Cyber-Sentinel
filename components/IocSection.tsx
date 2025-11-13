
import React from 'react';
import type { IndicatorOfCompromise, IocType } from '../types';
import { HashIcon, GlobeAltIcon, AtSymbolIcon, LinkIcon, QuestionMarkCircleIcon, ListBulletIcon } from './icons';

interface IocSectionProps {
  iocs: IndicatorOfCompromise[];
}

const IocIcon: React.FC<{ type: IocType }> = ({ type }) => {
    const iconClass = "h-5 w-5 text-sentinel-blue";
    switch(type) {
        case 'IP Address': return <GlobeAltIcon className={iconClass} />;
        case 'File Hash': return <HashIcon className={iconClass} />;
        case 'Domain': return <GlobeAltIcon className={iconClass} />;
        case 'URL': return <LinkIcon className={iconClass} />;
        case 'Email': return <AtSymbolIcon className={iconClass} />;
        default: return <QuestionMarkCircleIcon className={iconClass} />;
    }
};

const Card: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="bg-sentinel-gray-medium rounded-lg shadow-lg p-6 border border-sentinel-gray-light h-full">
    {children}
  </div>
);

const IocSection: React.FC<IocSectionProps> = ({ iocs }) => {
  return (
    <Card>
      <h2 className="text-xl font-bold text-gray-100 mb-4 flex items-center">
        <ListBulletIcon className="h-6 w-6 mr-3 text-sentinel-blue" />
        Indicators of Compromise
      </h2>
      <div className="space-y-3">
        {iocs.length > 0 ? iocs.map((ioc, index) => (
          <div key={index} className="bg-sentinel-gray-dark p-3 rounded-md flex items-center justify-between transition hover:bg-sentinel-gray-light">
            <div className="flex items-center">
              <IocIcon type={ioc.type} />
              <span className="ml-3 text-sm font-semibold text-gray-400 mr-2">{ioc.type}:</span>
              <code className="text-sm text-cyan-300 break-all">{ioc.value}</code>
            </div>
          </div>
        )) : (
            <p className="text-gray-400">No IoCs were automatically extracted.</p>
        )}
      </div>
    </Card>
  );
};

export default IocSection;
